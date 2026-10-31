//! offloader: move a file elsewhere, leave an encrypted retrieval record in its place.
//!
//!   offloader push <file> [--method dir|shell] [--dir PATH] [--put CMD --get CMD]
//!                         [--rm CMD] [--ext EXT] [--tmp PATH] [--no-verify]
//!   offloader pull <file.EXT> [--purge] [--rm CMD] [--ext EXT] [--tmp PATH]
//!
//! Every flag falls back to an env var (see `Flag::env`).
//!
//! Methods:
//!   dir   – copy the encrypted blob into a directory (NAS mount, USB, …).
//!   shell – run user commands under `sh -c` with $SRC / $DST / $ID in the env.
//!           Values go via env, never spliced into the command, so filenames can't inject.
//!           e.g. --put 'rclone copyto "$SRC" r:b/$ID' --get 'rclone copyto r:b/$ID "$DST"'
//!                --rm 'rclone deletefile r:b/$ID'
//!
//! `--purge` on pull deletes the remote copy after a successful restore. For shell, the
//! `--rm` command given at push is stored in the record; `--rm` at pull overrides it.
//!
//! The file is age/X25519-encrypted with a fresh key before leaving the machine; the
//! record (key, id, method) is age/scrypt-encrypted with your passphrase.

use age::secrecy::{ExposeSecret, SecretString};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::str::FromStr;

/// Fixed vocabulary: every name the program knows lives here.
mod vocab {
    pub const PROGRAM: &str = "offloader";
    pub const RECORD_MAGIC: &str = "offloader-v1";
    pub const DEFAULT_EXT: &str = "offload";
    pub const PARTIAL_SUFFIX: &str = "-partial";
    pub const TMP_PREFIX: &str = "offloader-";
    pub const BLOB_NAME: &str = "blob";
    pub const VERIFY_NAME: &str = "verify";
    pub const SHELL: &str = "sh";
    pub const SHELL_FLAG: &str = "-c";
    pub const RECORD_SEP: char = '=';
    pub const ID_BYTES: usize = 16;
    pub const COMPARE_BUF: usize = 64 * 1024;
    pub const PRIVATE_FILE_MODE: u32 = 0o600;
    pub const PRIVATE_DIR_MODE: u32 = 0o700;
    pub const PROMPT_PASS: &str = "record passphrase: ";
    pub const PROMPT_CONFIRM: &str = "confirm passphrase: ";
    pub const ENV_PASSPHRASE: &str = "OFFLOADER_PASSPHRASE";
    /// Accepted (case-insensitive) values for on/off env vars.
    pub const SWITCH_ON: [&str; 4] = ["1", "true", "yes", "on"];
    pub const SWITCH_OFF: [&str; 5] = ["", "0", "false", "no", "off"];
}
use vocab::*;

// ---------- enums ----------

#[derive(Clone, Copy)]
enum Cmd {
    Push,
    Pull,
}
impl Cmd {
    const ALL: [Cmd; 2] = [Self::Push, Self::Pull];
    fn name(self) -> &'static str {
        match self {
            Self::Push => "push",
            Self::Pull => "pull",
        }
    }
}
impl FromStr for Cmd {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        Self::ALL
            .into_iter()
            .find(|c| c.name() == s)
            .ok_or_else(|| Error::Usage(format!("unknown command {s:?}")))
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Flag {
    Method,
    Dir,
    Put,
    Get,
    Rm,
    Ext,
    Tmp,
    NoVerify,
    Purge,
    NoPurge,
    Help,
}
impl Flag {
    const ALL: [Flag; 11] = [
        Self::Method, Self::Dir, Self::Put, Self::Get, Self::Rm, Self::Ext, Self::Tmp, Self::NoVerify, Self::Purge,
        Self::NoPurge, Self::Help,
    ];
    fn name(self) -> &'static str {
        match self {
            Self::Method => "--method",
            Self::Dir => "--dir",
            Self::Put => "--put",
            Self::Get => "--get",
            Self::Rm => "--rm",
            Self::Ext => "--ext",
            Self::Tmp => "--tmp",
            Self::NoVerify => "--no-verify",
            Self::Purge => "--purge",
            Self::NoPurge => "--no-purge",
            Self::Help => "--help",
        }
    }
    fn env(self) -> Option<&'static str> {
        match self {
            Self::Method => Some("OFFLOADER_METHOD"),
            Self::Dir => Some("OFFLOADER_DIR"),
            Self::Put => Some("OFFLOADER_PUT"),
            Self::Get => Some("OFFLOADER_GET"),
            Self::Rm => Some("OFFLOADER_RM"),
            Self::Ext => Some("OFFLOADER_EXT"),
            Self::Tmp => Some("OFFLOADER_TMP"),
            Self::NoVerify => Some("OFFLOADER_NO_VERIFY"),
            Self::Purge => Some("OFFLOADER_PURGE"),
            Self::NoPurge | Self::Help => None,
        }
    }
    fn takes_value(self) -> bool {
        !matches!(self, Self::NoVerify | Self::Purge | Self::NoPurge | Self::Help)
    }
    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|f| f.name() == s)
    }
}

#[derive(Clone, Copy)]
enum MethodKind {
    Dir,
    Shell,
}
impl MethodKind {
    fn name(self) -> &'static str {
        match self {
            Self::Dir => "dir",
            Self::Shell => "shell",
        }
    }
}
impl FromStr for MethodKind {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        [Self::Dir, Self::Shell]
            .into_iter()
            .find(|m| m.name() == s)
            .ok_or_else(|| Error::Usage(format!("unknown method {s:?}")))
    }
}

/// How a blob gets out and back. Stored in the record.
enum Method {
    Dir(PathBuf),
    Shell { put: String, get: String, rm: Option<String> },
}

/// Env vars exposed to shell commands.
#[derive(Clone, Copy)]
enum ShellVar {
    Src,
    Dst,
    Id,
}
impl ShellVar {
    fn name(self) -> &'static str {
        match self {
            Self::Src => "SRC",
            Self::Dst => "DST",
            Self::Id => "ID",
        }
    }
}

/// Keys of the `key=value` lines inside a decrypted record.
#[derive(Clone, Copy, PartialEq)]
enum Field {
    Magic,
    Id,
    Key,
    Method,
    Dir,
    Get,
    Rm,
}
impl Field {
    const ALL: [Field; 7] = [Self::Magic, Self::Id, Self::Key, Self::Method, Self::Dir, Self::Get, Self::Rm];
    fn name(self) -> &'static str {
        match self {
            Self::Magic => "magic",
            Self::Id => "id",
            Self::Key => "key",
            Self::Method => "method",
            Self::Dir => "dir",
            Self::Get => "get",
            Self::Rm => "rm",
        }
    }
}

#[derive(Debug)]
enum Error {
    Usage(String),
    Io(io::Error),
    Encrypt(age::EncryptError),
    Decrypt(age::DecryptError),
    Exists(PathBuf),
    NotRegularFile(PathBuf),
    WrongExtension(String),
    EmptyPassphrase,
    PassphraseMismatch,
    Rng(String),
    CommandFailed { cmd: String, status: ExitStatus },
    VerifyMismatch,
    NoRemover,
    RemoteKept { id: String, cause: Box<Error> },
    Record(&'static str),
    BadValue { what: &'static str, why: &'static str },
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Usage(m) => write!(f, "{m}\n\n{}", usage()),
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Encrypt(e) => write!(f, "encrypt: {e}"),
            Self::Decrypt(e) => write!(f, "decrypt: {e}"),
            Self::Exists(p) => write!(f, "{} already exists", p.display()),
            Self::NotRegularFile(p) => write!(f, "{} is not a regular file", p.display()),
            Self::WrongExtension(e) => write!(f, "expected a .{e} file"),
            Self::EmptyPassphrase => write!(f, "empty passphrase"),
            Self::PassphraseMismatch => write!(f, "passphrases differ"),
            Self::Rng(e) => write!(f, "rng: {e}"),
            Self::CommandFailed { cmd, status } => write!(f, "command failed ({status}): {cmd}"),
            Self::VerifyMismatch => write!(f, "verify failed: fetched copy differs; original untouched"),
            Self::NoRemover => write!(f, "{} with shell method needs {} (at push or pull)", Flag::Purge.name(), Flag::Rm.name()),
            Self::RemoteKept { id, cause } => write!(f, "file restored, but remote copy {id} was not removed: {cause}"),
            Self::Record(m) => write!(f, "bad record: {m}"),
            Self::BadValue { what, why } => write!(f, "{what}: {why}"),
        }
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<age::EncryptError> for Error {
    fn from(e: age::EncryptError) -> Self {
        Self::Encrypt(e)
    }
}
impl From<age::DecryptError> for Error {
    fn from(e: age::DecryptError) -> Self {
        Self::Decrypt(e)
    }
}
type R<T> = Result<T, Error>;

// ---------- config ----------

struct Config {
    cmd: Cmd,
    target: PathBuf,
    ext: String,
    tmp_root: PathBuf,
    verify: bool,
    purge: bool,
    values: Vec<(Flag, String)>,
}
impl Config {
    fn parse(args: impl Iterator<Item = String>) -> R<Option<Self>> {
        let mut values = vec![];
        let mut pos = vec![];
        let mut it = args;
        while let Some(a) = it.next() {
            match Flag::parse(&a) {
                Some(Flag::Help) => return Ok(None),
                Some(f) if f.takes_value() => {
                    let v = it.next().ok_or_else(|| Error::Usage(format!("{} needs a value", f.name())))?;
                    values.push((f, v));
                }
                Some(f) => values.push((f, String::new())),
                None if a.starts_with("--") => return Err(Error::Usage(format!("unknown flag {a}"))),
                None => pos.push(a),
            }
        }
        let [cmd, target] = <[String; 2]>::try_from(pos)
            .map_err(|_| Error::Usage("expected <command> <file>".into()))?;
        let mut c = Self {
            cmd: cmd.parse()?,
            target: target.into(),
            ext: String::new(),
            tmp_root: PathBuf::new(),
            verify: true,
            purge: false,
            values,
        };
        c.ext = c.get(Flag::Ext).unwrap_or_else(|| DEFAULT_EXT.into());
        if c.ext.is_empty() || c.ext.contains(['/', '.']) {
            return Err(Error::BadValue { what: Flag::Ext.name(), why: "must be non-empty, no '/' or '.'" });
        }
        c.tmp_root = c.get(Flag::Tmp).map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
        c.verify = !c.switch(Flag::NoVerify)?;
        c.purge = match (c.on_cli(Flag::Purge), c.on_cli(Flag::NoPurge)) {
            (true, true) => {
                return Err(Error::Usage(format!("{} and {} conflict", Flag::Purge.name(), Flag::NoPurge.name())));
            }
            (_, true) => false,
            _ => c.switch(Flag::Purge)?,
        };
        Ok(Some(c))
    }

    /// CLI value, else env var.
    fn get(&self, f: Flag) -> Option<String> {
        self.values
            .iter()
            .rev()
            .find(|(k, _)| *k == f)
            .map(|(_, v)| v.clone())
            .or_else(|| f.env().and_then(|e| std::env::var(e).ok()))
    }
    fn on_cli(&self, f: Flag) -> bool {
        self.values.iter().any(|(k, _)| *k == f)
    }

    /// On/off flag: present on the CLI = on; else its env var must be a SWITCH_ON/OFF word.
    fn switch(&self, f: Flag) -> R<bool> {
        if self.on_cli(f) {
            return Ok(true);
        }
        let Some(v) = f.env().and_then(|e| std::env::var(e).ok()) else { return Ok(false) };
        let v = v.to_ascii_lowercase();
        if SWITCH_ON.contains(&v.as_str()) {
            Ok(true)
        } else if SWITCH_OFF.contains(&v.as_str()) {
            Ok(false)
        } else {
            Err(Error::BadValue { what: f.env().unwrap_or_default(), why: "expected 1/0, true/false, yes/no, on/off" })
        }
    }

    fn need(&self, f: Flag) -> R<String> {
        self.get(f).ok_or_else(|| {
            Error::Usage(format!("missing {} (or ${})", f.name(), f.env().unwrap_or_default()))
        })
    }

    fn method(&self) -> R<Method> {
        let kind: MethodKind = self.get(Flag::Method).as_deref().unwrap_or(MethodKind::Shell.name()).parse()?;
        let m = match kind {
            MethodKind::Dir if self.get(Flag::Rm).is_some() => {
                return Err(Error::BadValue { what: Flag::Rm.name(), why: "only applies to the shell method" });
            }
            MethodKind::Dir => Method::Dir(self.need(Flag::Dir)?.into()),
            MethodKind::Shell => {
                Method::Shell { put: self.need(Flag::Put)?, get: self.need(Flag::Get)?, rm: self.get(Flag::Rm) }
            }
        };
        m.validate()?;
        Ok(m)
    }

    fn record_path(&self, file: &Path) -> PathBuf {
        let mut s = file.as_os_str().to_owned();
        s.push(format!(".{}", self.ext));
        s.into()
    }
}

// ---------- method ----------

impl Method {
    fn kind(&self) -> MethodKind {
        match self {
            Self::Dir(_) => MethodKind::Dir,
            Self::Shell { .. } => MethodKind::Shell,
        }
    }

    /// Values end up as single record lines, so no newlines; dir must be absolute UTF-8
    /// so pull works from any cwd.
    fn validate(&self) -> R<()> {
        let bad = |what, why| Err(Error::BadValue { what, why });
        match self {
            Self::Dir(d) => match d.to_str() {
                None => bad(Flag::Dir.name(), "must be UTF-8"),
                Some(s) if s.contains('\n') => bad(Flag::Dir.name(), "must not contain newlines"),
                Some(_) if !d.is_absolute() => bad(Flag::Dir.name(), "must be absolute"),
                Some(_) if !d.is_dir() => bad(Flag::Dir.name(), "is not a directory"),
                Some(_) => Ok(()),
            },
            Self::Shell { put, get, rm } => {
                if [put, get].into_iter().chain(rm).any(|c| c.contains('\n')) {
                    bad("shell command", "must not contain newlines")
                } else {
                    Ok(())
                }
            }
        }
    }

    fn put(&self, src: &Path, id: &str) -> R<()> {
        match self {
            Self::Dir(d) => {
                let mut out = private_file(&d.join(id))?;
                io::copy(&mut File::open(src)?, &mut out)?;
                Ok(out.sync_all()?)
            }
            Self::Shell { put, .. } => sh(put, &[(ShellVar::Src, src.as_os_str()), (ShellVar::Id, id.as_ref())]),
        }
    }

    fn get(&self, dst: &Path, id: &str) -> R<()> {
        match self {
            Self::Dir(d) => {
                io::copy(&mut File::open(d.join(id))?, &mut private_file(dst)?)?;
                Ok(())
            }
            Self::Shell { get, .. } => sh(get, &[(ShellVar::Dst, dst.as_os_str()), (ShellVar::Id, id.as_ref())]),
        }
    }

    fn can_remove(&self) -> bool {
        matches!(self, Self::Dir(_) | Self::Shell { rm: Some(_), .. })
    }

    fn remove(&self, id: &str) -> R<()> {
        match self {
            Self::Dir(d) => Ok(fs::remove_file(d.join(id))?),
            Self::Shell { rm: Some(rm), .. } => sh(rm, &[(ShellVar::Id, id.as_ref())]),
            Self::Shell { rm: None, .. } => Err(Error::NoRemover),
        }
    }
}

fn sh(cmd: &str, env: &[(ShellVar, &std::ffi::OsStr)]) -> R<()> {
    let status = Command::new(SHELL)
        .arg(SHELL_FLAG)
        .arg(cmd)
        .envs(env.iter().map(|(k, v)| (k.name(), v)))
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::CommandFailed { cmd: cmd.into(), status })
    }
}

// ---------- record ----------

struct Record {
    id: String,
    key: age::x25519::Identity,
    method: Method,
}
impl Record {
    fn encode(&self) -> SecretString {
        let mut lines = vec![
            (Field::Magic, RECORD_MAGIC.to_string()),
            (Field::Id, self.id.clone()),
            (Field::Key, self.key.to_string().expose_secret().to_string()),
            (Field::Method, self.method.kind().name().to_string()),
        ];
        match &self.method {
            // validate() guaranteed UTF-8.
            Method::Dir(d) => lines.push((Field::Dir, d.to_string_lossy().into_owned())),
            Method::Shell { get, rm, .. } => {
                lines.push((Field::Get, get.clone()));
                lines.extend(rm.clone().map(|r| (Field::Rm, r)));
            }
        }
        lines
            .iter()
            .map(|(k, v)| format!("{}{RECORD_SEP}{v}\n", k.name()))
            .collect::<String>()
            .into()
    }

    fn decode(body: &str) -> R<Self> {
        let mut map: Vec<(Field, &str)> = vec![];
        for line in body.lines() {
            let (k, v) = line.split_once(RECORD_SEP).ok_or(Error::Record("line without separator"))?;
            let f = Field::ALL.into_iter().find(|f| f.name() == k).ok_or(Error::Record("unknown field"))?;
            map.push((f, v));
        }
        let field = |f: Field| map.iter().find(|(k, _)| *k == f).map(|(_, v)| *v).ok_or(Error::Record("missing field"));
        if field(Field::Magic)? != RECORD_MAGIC {
            return Err(Error::Record("unsupported version"));
        }
        let id = field(Field::Id)?.to_string();
        if id.len() != ID_BYTES * 2 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Record("malformed id"));
        }
        let key = field(Field::Key)?.parse().map_err(|_| Error::Record("malformed key"))?;
        let method = match field(Field::Method)?.parse::<MethodKind>().map_err(|_| Error::Record("unknown method"))? {
            MethodKind::Dir => Method::Dir(field(Field::Dir)?.into()),
            // put isn't needed to retrieve, so it isn't stored.
            MethodKind::Shell => Method::Shell {
                put: String::new(),
                get: field(Field::Get)?.into(),
                rm: field(Field::Rm).ok().map(String::from),
            },
        };
        Ok(Self { id, key, method })
    }
}

// ---------- commands ----------

fn push(cfg: &Config) -> R<()> {
    let file = &cfg.target;
    if !fs::metadata(file)?.is_file() {
        return Err(Error::NotRegularFile(file.clone()));
    }
    let record_path = cfg.record_path(file);
    if record_path.exists() {
        return Err(Error::Exists(record_path));
    }
    let method = cfg.method()?;
    let pass = passphrase(true)?;
    let rec = Record { id: random_id()?, key: age::x25519::Identity::generate(), method };
    let tmp = TmpDir::new(&cfg.tmp_root, &rec.id)?;

    let blob = tmp.0.join(BLOB_NAME);
    let recipient = rec.key.to_public();
    let mut w = age::Encryptor::with_recipients(std::iter::once(&recipient as _))?.wrap_output(private_file(&blob)?)?;
    io::copy(&mut File::open(file)?, &mut w)?;
    w.finish()?.sync_all()?;

    rec.method.put(&blob, &rec.id)?;

    if cfg.verify {
        let back = tmp.0.join(VERIFY_NAME);
        rec.method.get(&back, &rec.id)?;
        if !same(&mut decrypt(&back, &rec.key)?, &mut BufReader::new(File::open(file)?))? {
            return Err(Error::VerifyMismatch);
        }
    }

    // Record durable on disk before the original goes away.
    let mut w = age::Encryptor::with_user_passphrase(pass).wrap_output(private_file(&record_path)?)?;
    w.write_all(rec.encode().expose_secret().as_bytes())?;
    w.finish()?.sync_all()?;
    fs::remove_file(file)?;
    println!("offloaded {} -> {} (id {})", file.display(), record_path.display(), rec.id);
    Ok(())
}

fn pull(cfg: &Config) -> R<()> {
    let record_path = &cfg.target;
    if record_path.extension().is_none_or(|e| e != cfg.ext.as_str()) {
        return Err(Error::WrongExtension(cfg.ext.clone()));
    }
    let out = record_path.with_extension("");
    if out.exists() {
        return Err(Error::Exists(out));
    }
    let pass = passphrase(false)?;
    let mut body = String::new();
    age::Decryptor::new(BufReader::new(File::open(record_path)?))?
        .decrypt(std::iter::once(&age::scrypt::Identity::new(pass) as _))?
        .read_to_string(&mut body)?;
    let mut rec = Record::decode(&body)?;
    if let (Method::Shell { rm, .. }, Some(over)) = (&mut rec.method, cfg.get(Flag::Rm)) {
        *rm = Some(over);
        rec.method.validate()?;
    }
    // Fail before touching anything if purge can't be honored.
    if cfg.purge && !rec.method.can_remove() {
        return Err(Error::NoRemover);
    }

    let tmp = TmpDir::new(&cfg.tmp_root, &rec.id)?;
    let blob = tmp.0.join(BLOB_NAME);
    rec.method.get(&blob, &rec.id)?;

    // AEAD fails on any tampering/truncation, so rename only happens for authentic plaintext.
    let mut partial = out.clone().into_os_string();
    partial.push(PARTIAL_SUFFIX);
    let partial = PathBuf::from(partial);
    let res = (|| -> R<()> {
        let mut w = private_file(&partial)?;
        io::copy(&mut decrypt(&blob, &rec.key)?, &mut w)?;
        Ok(w.sync_all()?)
    })();
    if let Err(e) = res {
        let _ = fs::remove_file(&partial);
        return Err(e);
    }
    fs::rename(&partial, &out)?;
    fs::remove_file(record_path)?;
    println!("restored {}", out.display());
    // Only after the plaintext is safely in place.
    if cfg.purge {
        rec.method.remove(&rec.id).map_err(|e| Error::RemoteKept { id: rec.id.clone(), cause: Box::new(e) })?;
        println!("removed remote copy {}", rec.id);
    }
    Ok(())
}

// ---------- helpers ----------

fn decrypt(p: &Path, key: &age::x25519::Identity) -> R<impl Read> {
    Ok(age::Decryptor::new(BufReader::new(File::open(p)?))?.decrypt(std::iter::once(key as _))?)
}

fn passphrase(confirm: bool) -> R<SecretString> {
    if let Ok(p) = std::env::var(ENV_PASSPHRASE) {
        return if p.is_empty() { Err(Error::EmptyPassphrase) } else { Ok(p.into()) };
    }
    let p = rpassword::prompt_password(PROMPT_PASS)?;
    if p.is_empty() {
        return Err(Error::EmptyPassphrase);
    }
    if confirm && rpassword::prompt_password(PROMPT_CONFIRM)? != p {
        return Err(Error::PassphraseMismatch);
    }
    Ok(p.into())
}

fn random_id() -> R<String> {
    let mut b = [0u8; ID_BYTES];
    getrandom::fill(&mut b).map_err(|e| Error::Rng(e.to_string()))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

fn private_file(p: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).mode(PRIVATE_FILE_MODE).open(p)
}

fn same(a: &mut impl Read, b: &mut impl Read) -> io::Result<bool> {
    let (mut x, mut y) = (vec![0u8; COMPARE_BUF], vec![0u8; COMPARE_BUF]);
    loop {
        let n = read_full(a, &mut x)?;
        if n != read_full(b, &mut y)? || x[..n] != y[..n] {
            return Ok(false);
        }
        if n == 0 {
            return Ok(true);
        }
    }
}

fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

/// Private scratch dir, removed on drop (including error paths).
struct TmpDir(PathBuf);
impl TmpDir {
    fn new(root: &Path, id: &str) -> io::Result<Self> {
        let p = root.join(format!("{TMP_PREFIX}{id}"));
        fs::DirBuilder::new().mode(PRIVATE_DIR_MODE).create(&p)?;
        Ok(Self(p))
    }
}
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn usage() -> String {
    let flags = Flag::ALL
        .iter()
        .map(|f| match f.env() {
            Some(e) => format!("  {:<12} ${e}", f.name()),
            None => format!("  {}", f.name()),
        })
        .collect::<Vec<_>>()
        .join("\n");
    let cmds = Cmd::ALL.map(Cmd::name).join("|");
    let methods = [MethodKind::Dir, MethodKind::Shell].map(MethodKind::name).join("|");
    format!(
        "usage: {PROGRAM} {cmds} <file> [flags]\nmethods: {methods}\nshell vars: ${} ${} ${}\npassphrase: ${ENV_PASSPHRASE} or prompt\nflags (env fallback):\n{flags}",
        ShellVar::Src.name(),
        ShellVar::Dst.name(),
        ShellVar::Id.name()
    )
}

fn main() {
    let res = Config::parse(std::env::args().skip(1)).and_then(|c| match c {
        None => {
            println!("{}", usage());
            Ok(())
        }
        Some(c) => match c.cmd {
            Cmd::Push => push(&c),
            Cmd::Pull => pull(&c),
        },
    });
    if let Err(e) = res {
        eprintln!("{PROGRAM}: {e}");
        std::process::exit(1);
    }
}
