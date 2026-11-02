//! offloader: move a file elsewhere, leave an encrypted retrieval record in its place.
//!
//! The file is age/X25519-encrypted with a fresh key before leaving the machine; the
//! record (key, id, method, file metadata) is age/scrypt-encrypted with your passphrase.
//! CLI surface lives in the clap structs below; `offloader --help` documents it.

use age::secrecy::{ExposeSecret, SecretString};
use clap::builder::BoolishValueParser;
use clap::error::ErrorKind;
use clap::{ArgAction, Args, CommandFactory, Parser, Subcommand, ValueEnum};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Fixed vocabulary: every name the program knows lives here.
mod vocab {
    pub const PROGRAM: &str = "offloader";
    pub const RECORD_MAGIC: &str = "offloader-v1";
    pub const DEFAULT_EXT: &str = "offload";
    /// Hidden temp file next to the restore target, renamed into place when complete.
    pub const PARTIAL_PREFIX: &str = ".offloader-partial-";
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
    /// Permission bits carried in the record (rwx for u/g/o + setuid/setgid/sticky).
    pub const MODE_MASK: u32 = 0o7777;
    pub const MODE_RADIX: u32 = 8;
    pub const PROMPT_PASS: &str = "record passphrase: ";
    pub const PROMPT_CONFIRM: &str = "confirm passphrase: ";
    pub const METHOD_DIR: &str = "dir";
    pub const METHOD_SHELL: &str = "shell";

    /// Long flag names (without the leading `--`).
    pub mod flag {
        pub const METHOD: &str = "method";
        pub const DIR: &str = "dir";
        pub const PUT: &str = "put";
        pub const GET: &str = "get";
        pub const RM: &str = "rm";
        pub const EXT: &str = "ext";
        pub const TMP: &str = "tmp";
        pub const NO_VERIFY: &str = "no-verify";
        pub const PURGE: &str = "purge";
        pub const NO_PURGE: &str = "no-purge";
    }

    /// Env var fallbacks for flags, plus the passphrase.
    pub mod env {
        pub const METHOD: &str = "OFFLOADER_METHOD";
        pub const DIR: &str = "OFFLOADER_DIR";
        pub const PUT: &str = "OFFLOADER_PUT";
        pub const GET: &str = "OFFLOADER_GET";
        pub const RM: &str = "OFFLOADER_RM";
        pub const EXT: &str = "OFFLOADER_EXT";
        pub const TMP: &str = "OFFLOADER_TMP";
        pub const NO_VERIFY: &str = "OFFLOADER_NO_VERIFY";
        pub const PURGE: &str = "OFFLOADER_PURGE";
        pub const PASSPHRASE: &str = "OFFLOADER_PASSPHRASE";
    }
}
use vocab::*;

// ---------- CLI ----------

#[derive(Parser)]
#[command(name = PROGRAM, version, about, after_help = after_help())]
struct Cli {
    #[command(flatten)]
    common: Common,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args)]
struct Common {
    /// Record file extension
    #[arg(long = flag::EXT, env = env::EXT, default_value = DEFAULT_EXT, value_parser = parse_ext, global = true)]
    ext: String,
    /// Root for private scratch dirs
    #[arg(long = flag::TMP, env = env::TMP, global = true, default_value_os_t = std::env::temp_dir())]
    tmp: PathBuf,
}

#[derive(Subcommand)]
enum Cmd {
    /// Encrypt + upload FILE, verify, then replace it with FILE.<ext>
    Push(PushArgs),
    /// Fetch + decrypt the file a record points to, restoring it in place
    Pull(PullArgs),
}

#[derive(Args)]
struct PushArgs {
    file: PathBuf,
    /// How the blob leaves the machine
    #[arg(id = flag::METHOD, long = flag::METHOD, env = env::METHOD, value_enum, default_value_t = MethodKind::Shell)]
    method: MethodKind,
    /// Target directory (absolute) for the dir method
    #[arg(long = flag::DIR, env = env::DIR, value_parser = parse_dir, required_if_eq(flag::METHOD, METHOD_DIR))]
    dir: Option<PathBuf>,
    /// Upload command (shell method)
    #[arg(long = flag::PUT, env = env::PUT, value_parser = parse_cmd)]
    put: Option<String>,
    /// Download command (shell method; stored in the record)
    #[arg(long = flag::GET, env = env::GET, value_parser = parse_cmd)]
    get: Option<String>,
    /// Remove command for later purges (shell method; stored in the record)
    #[arg(long = flag::RM, env = env::RM, value_parser = parse_cmd)]
    rm: Option<String>,
    /// Skip downloading the copy back to verify it before deleting the original
    #[arg(long = flag::NO_VERIFY, env = env::NO_VERIFY, action = ArgAction::SetTrue, value_parser = BoolishValueParser::new())]
    no_verify: bool,
}

#[derive(Args)]
struct PullArgs {
    record: PathBuf,
    /// Delete the remote copy after a successful restore
    #[arg(long = flag::PURGE, env = env::PURGE, action = ArgAction::SetTrue, value_parser = BoolishValueParser::new())]
    purge: bool,
    /// Keep the remote copy; always wins over --purge / $OFFLOADER_PURGE
    #[arg(long = flag::NO_PURGE, action = ArgAction::SetTrue)]
    no_purge: bool,
    /// Remove command, overriding the one stored in the record (shell method)
    #[arg(long = flag::RM, env = env::RM, value_parser = parse_cmd)]
    rm: Option<String>,
}

fn parse_ext(s: &str) -> Result<String, String> {
    if s.is_empty() || s.contains(['/', '.']) {
        Err("must be non-empty, no '/' or '.'".into())
    } else {
        Ok(s.into())
    }
}

/// Stored in the record and used from any cwd at pull time: absolute, UTF-8, one line.
fn parse_dir(s: &str) -> Result<PathBuf, String> {
    let p = PathBuf::from(s);
    match () {
        _ if s.contains('\n') => Err("must not contain newlines".into()),
        _ if !p.is_absolute() => Err("must be absolute".into()),
        _ if !p.is_dir() => Err("is not a directory".into()),
        _ => Ok(p),
    }
}

/// Commands are stored as single record lines.
fn parse_cmd(s: &str) -> Result<String, String> {
    if s.contains('\n') {
        Err("must not contain newlines".into())
    } else {
        Ok(s.into())
    }
}

fn after_help() -> String {
    format!(
        "Shell commands run under `{SHELL} {SHELL_FLAG}` with ${}, ${}, ${} in the env.\nPassphrase: ${} or prompt.",
        ShellVar::Src.name(),
        ShellVar::Dst.name(),
        ShellVar::Id.name(),
        env::PASSPHRASE
    )
}

impl Common {
    fn record_path(&self, file: &Path) -> PathBuf {
        let mut s = file.as_os_str().to_owned();
        s.push(format!(".{}", self.ext));
        s.into()
    }
}

impl PushArgs {
    /// `--dir` is enforced by clap's `required_if_eq` (dir is never the default method).
    /// `--put`/`--get` are checked here: `required_if_eq` ignores default values, and shell
    /// is the default. Errors go through clap so they look and exit like its own.
    fn method(&self) -> R<Method> {
        let cli_err = |kind, msg: String| Error::Cli(Cli::command().error(kind, msg));
        let need = |v: &Option<String>, flag: &str, env: &str| {
            v.clone().ok_or_else(|| {
                cli_err(
                    ErrorKind::MissingRequiredArgument,
                    format!(
                        "--{flag} (or ${env}) is required for --{} {METHOD_SHELL}",
                        flag::METHOD
                    ),
                )
            })
        };
        Ok(match self.method {
            MethodKind::Dir if self.rm.is_some() => {
                return Err(cli_err(
                    ErrorKind::ArgumentConflict,
                    format!(
                        "--{} only applies to --{} {METHOD_SHELL}",
                        flag::RM,
                        flag::METHOD
                    ),
                ));
            }
            MethodKind::Dir => {
                Method::Dir(self.dir.clone().expect("enforced by clap required_if_eq"))
            }
            MethodKind::Shell => Method::Shell {
                put: need(&self.put, flag::PUT, env::PUT)?,
                get: need(&self.get, flag::GET, env::GET)?,
                rm: self.rm.clone(),
            },
        })
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum MethodKind {
    /// Copy into a local directory (NAS mount, USB, …)
    #[value(name = METHOD_DIR)]
    Dir,
    /// Run user-supplied put/get/rm commands
    #[value(name = METHOD_SHELL)]
    Shell,
}
impl MethodKind {
    fn name(self) -> String {
        self.to_possible_value()
            .expect("no skipped variants")
            .get_name()
            .to_owned()
    }
    fn parse(s: &str) -> Option<Self> {
        <Self as ValueEnum>::from_str(s, false).ok()
    }
}

/// How a blob gets out and back. Stored in the record.
enum Method {
    Dir(PathBuf),
    Shell {
        put: String,
        get: String,
        rm: Option<String>,
    },
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
    Mode,
    Mtime,
    Atime,
}
impl Field {
    const ALL: [Field; 10] = [
        Self::Magic,
        Self::Id,
        Self::Key,
        Self::Method,
        Self::Dir,
        Self::Get,
        Self::Rm,
        Self::Mode,
        Self::Mtime,
        Self::Atime,
    ];
    fn name(self) -> &'static str {
        match self {
            Self::Magic => "magic",
            Self::Id => "id",
            Self::Key => "key",
            Self::Method => "method",
            Self::Dir => "dir",
            Self::Get => "get",
            Self::Rm => "rm",
            Self::Mode => "mode",
            Self::Mtime => "mtime",
            Self::Atime => "atime",
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("encrypt: {0}")]
    Encrypt(#[from] age::EncryptError),
    #[error("decrypt: {0}")]
    Decrypt(#[from] age::DecryptError),
    #[error("{} already exists", .0.display())]
    Exists(PathBuf),
    #[error("{} is not a regular file", .0.display())]
    NotRegularFile(PathBuf),
    #[error("expected a .{0} file")]
    WrongExtension(String),
    #[error("empty passphrase")]
    EmptyPassphrase,
    #[error("passphrases differ")]
    PassphraseMismatch,
    #[error("rng: {0}")]
    Rng(String),
    #[error("command failed ({status}): {cmd}")]
    CommandFailed { cmd: String, status: ExitStatus },
    #[error("verify failed: fetched copy differs; original untouched")]
    VerifyMismatch,
    #[error("--{purge} with the shell method needs --{rm} (at push or pull)", purge = flag::PURGE, rm = flag::RM)]
    NoRemover,
    #[error("file restored, but remote copy {id} was not removed: {cause}")]
    RemoteKept { id: String, cause: Box<Error> },
    #[error("bad record: {0}")]
    Record(&'static str),
    #[error(transparent)]
    Cli(clap::Error),
}
type R<T> = Result<T, Error>;

// ---------- method ----------

impl Method {
    fn kind(&self) -> MethodKind {
        match self {
            Self::Dir(_) => MethodKind::Dir,
            Self::Shell { .. } => MethodKind::Shell,
        }
    }

    fn put(&self, src: &Path, id: &str) -> R<()> {
        match self {
            Self::Dir(d) => {
                let mut out = private_file(&d.join(id))?;
                io::copy(&mut File::open(src)?, &mut out)?;
                Ok(out.sync_all()?)
            }
            Self::Shell { put, .. } => sh(
                put,
                &[
                    (ShellVar::Src, src.as_os_str()),
                    (ShellVar::Id, id.as_ref()),
                ],
            ),
        }
    }

    fn get(&self, dst: &Path, id: &str) -> R<()> {
        match self {
            Self::Dir(d) => {
                io::copy(&mut File::open(d.join(id))?, &mut private_file(dst)?)?;
                Ok(())
            }
            Self::Shell { get, .. } => sh(
                get,
                &[
                    (ShellVar::Dst, dst.as_os_str()),
                    (ShellVar::Id, id.as_ref()),
                ],
            ),
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
        Err(Error::CommandFailed {
            cmd: cmd.into(),
            status,
        })
    }
}

// ---------- record ----------

struct Record {
    id: String,
    key: age::x25519::Identity,
    method: Method,
    meta: Meta,
}

/// Original file metadata, restored on pull. Optional so older records still decode
/// (missing fields leave the restored file at the private defaults).
/// Owner isn't stored: only root could restore it, and pull runs as the user.
#[derive(Default)]
struct Meta {
    mode: Option<u32>,
    mtime: Option<SystemTime>,
    atime: Option<SystemTime>,
}
impl Meta {
    fn of(m: &fs::Metadata) -> Self {
        Self {
            mode: Some(m.permissions().mode() & MODE_MASK),
            mtime: m.modified().ok(),
            atime: m.accessed().ok(),
        }
    }

    /// Apply to an open file; call after the last write so mtime sticks.
    fn apply(&self, f: &File) -> io::Result<()> {
        if let Some(mode) = self.mode {
            f.set_permissions(fs::Permissions::from_mode(mode))?;
        }
        let mut times = fs::FileTimes::new();
        if let Some(t) = self.mtime {
            times = times.set_modified(t);
        }
        if let Some(t) = self.atime {
            times = times.set_accessed(t);
        }
        f.set_times(times)
    }

    fn encode(&self, lines: &mut Vec<(Field, String)>) {
        lines.extend(self.mode.map(|m| (Field::Mode, format!("{m:o}"))));
        lines.extend(
            self.mtime
                .map(|t| (Field::Mtime, time_to_nanos(t).to_string())),
        );
        lines.extend(
            self.atime
                .map(|t| (Field::Atime, time_to_nanos(t).to_string())),
        );
    }

    fn decode<'a>(field: impl Fn(Field) -> Option<&'a str>) -> R<Self> {
        let time = |f| {
            field(f)
                .map(|v| {
                    v.parse::<i128>()
                        .ok()
                        .and_then(nanos_to_time)
                        .ok_or(Error::Record("malformed time"))
                })
                .transpose()
        };
        let mode = field(Field::Mode)
            .map(|v| match u32::from_str_radix(v, MODE_RADIX) {
                Ok(m) if m & !MODE_MASK == 0 => Ok(m),
                _ => Err(Error::Record("malformed mode")),
            })
            .transpose()?;
        Ok(Self {
            mode,
            mtime: time(Field::Mtime)?,
            atime: time(Field::Atime)?,
        })
    }
}

/// Signed nanoseconds since the epoch (pre-1970 timestamps are legal on Unix).
fn time_to_nanos(t: SystemTime) -> i128 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i128,
        Err(e) => -(e.duration().as_nanos() as i128),
    }
}

fn nanos_to_time(n: i128) -> Option<SystemTime> {
    let d = Duration::from_nanos(u64::try_from(n.unsigned_abs()).ok()?);
    if n >= 0 {
        UNIX_EPOCH.checked_add(d)
    } else {
        UNIX_EPOCH.checked_sub(d)
    }
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
            // parse_dir accepted it from a &str, so it's UTF-8.
            Method::Dir(d) => lines.push((Field::Dir, d.to_string_lossy().into_owned())),
            Method::Shell { get, rm, .. } => {
                lines.push((Field::Get, get.clone()));
                lines.extend(rm.clone().map(|r| (Field::Rm, r)));
            }
        }
        self.meta.encode(&mut lines);
        lines
            .iter()
            .map(|(k, v)| format!("{}{RECORD_SEP}{v}\n", k.name()))
            .collect::<String>()
            .into()
    }

    fn decode(body: &str) -> R<Self> {
        let mut map: Vec<(Field, &str)> = vec![];
        for line in body.lines() {
            let (k, v) = line
                .split_once(RECORD_SEP)
                .ok_or(Error::Record("line without separator"))?;
            let f = Field::ALL
                .into_iter()
                .find(|f| f.name() == k)
                .ok_or(Error::Record("unknown field"))?;
            map.push((f, v));
        }
        let field = |f: Field| {
            map.iter()
                .find(|(k, _)| *k == f)
                .map(|(_, v)| *v)
                .ok_or(Error::Record("missing field"))
        };
        if field(Field::Magic)? != RECORD_MAGIC {
            return Err(Error::Record("unsupported version"));
        }
        let id = field(Field::Id)?.to_string();
        if id.len() != ID_BYTES * 2 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Record("malformed id"));
        }
        let key = field(Field::Key)?
            .parse()
            .map_err(|_| Error::Record("malformed key"))?;
        let method = match MethodKind::parse(field(Field::Method)?)
            .ok_or(Error::Record("unknown method"))?
        {
            MethodKind::Dir => Method::Dir(field(Field::Dir)?.into()),
            // put isn't needed to retrieve, so it isn't stored.
            MethodKind::Shell => Method::Shell {
                put: String::new(),
                get: field(Field::Get)?.into(),
                rm: field(Field::Rm).ok().map(String::from),
            },
        };
        let meta = Meta::decode(|f| field(f).ok())?;
        Ok(Self {
            id,
            key,
            method,
            meta,
        })
    }
}

// ---------- commands ----------

fn push(common: &Common, args: &PushArgs) -> R<()> {
    let file = &args.file;
    let file_meta = fs::metadata(file)?;
    if !file_meta.is_file() {
        return Err(Error::NotRegularFile(file.clone()));
    }
    let record_path = common.record_path(file);
    if record_path.exists() {
        return Err(Error::Exists(record_path));
    }
    let method = args.method()?;
    let pass = passphrase(true)?;
    let rec = Record {
        id: random_id()?,
        key: age::x25519::Identity::generate(),
        method,
        meta: Meta::of(&file_meta),
    };
    let tmp = scratch_dir(&common.tmp)?;

    let blob = tmp.path().join(BLOB_NAME);
    let recipient = rec.key.to_public();
    let mut w = age::Encryptor::with_recipients(std::iter::once(&recipient as _))?
        .wrap_output(private_file(&blob)?)?;
    io::copy(&mut File::open(file)?, &mut w)?;
    w.finish()?.sync_all()?;

    rec.method.put(&blob, &rec.id)?;

    if !args.no_verify {
        let back = tmp.path().join(VERIFY_NAME);
        rec.method.get(&back, &rec.id)?;
        if !same(
            &mut decrypt(&back, &rec.key)?,
            &mut BufReader::new(File::open(file)?),
        )? {
            return Err(Error::VerifyMismatch);
        }
    }

    // Record durable on disk before the original goes away.
    let mut w =
        age::Encryptor::with_user_passphrase(pass).wrap_output(private_file(&record_path)?)?;
    w.write_all(rec.encode().expose_secret().as_bytes())?;
    w.finish()?.sync_all()?;
    fs::remove_file(file)?;
    println!(
        "offloaded {} -> {} (id {})",
        file.display(),
        record_path.display(),
        rec.id
    );
    Ok(())
}

fn pull(common: &Common, args: &PullArgs) -> R<()> {
    let record_path = &args.record;
    let purge = args.purge && !args.no_purge;
    if record_path
        .extension()
        .is_none_or(|e| e != common.ext.as_str())
    {
        return Err(Error::WrongExtension(common.ext.clone()));
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
    if let (Method::Shell { rm, .. }, Some(over)) = (&mut rec.method, args.rm.clone()) {
        *rm = Some(over);
    }
    // Fail before touching anything if purge can't be honored.
    if purge && !rec.method.can_remove() {
        return Err(Error::NoRemover);
    }

    let tmp = scratch_dir(&common.tmp)?;
    let blob = tmp.path().join(BLOB_NAME);
    rec.method.get(&blob, &rec.id)?;

    // AEAD fails on any tampering/truncation, so only authentic plaintext gets persisted.
    // The temp file (0600) is deleted on drop if anything fails before that.
    let dir = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut w = tempfile::Builder::new()
        .prefix(PARTIAL_PREFIX)
        .permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))
        .tempfile_in(dir)?;
    io::copy(&mut decrypt(&blob, &rec.key)?, &mut w)?;
    rec.meta.apply(w.as_file())?;
    w.as_file().sync_all()?;
    // No-clobber: if something created `out` since the check above, fail instead of overwriting.
    w.persist_noclobber(&out)
        .map_err(|e| match e.error.kind() {
            io::ErrorKind::AlreadyExists => Error::Exists(out.clone()),
            _ => e.error.into(),
        })?;
    fs::remove_file(record_path)?;
    println!("restored {}", out.display());
    // Only after the plaintext is safely in place.
    if purge {
        rec.method.remove(&rec.id).map_err(|e| Error::RemoteKept {
            id: rec.id.clone(),
            cause: Box::new(e),
        })?;
        println!("removed remote copy {}", rec.id);
    }
    Ok(())
}

// ---------- helpers ----------

fn decrypt(p: &Path, key: &age::x25519::Identity) -> R<impl Read> {
    Ok(age::Decryptor::new(BufReader::new(File::open(p)?))?.decrypt(std::iter::once(key as _))?)
}

fn passphrase(confirm: bool) -> R<SecretString> {
    if let Ok(p) = std::env::var(env::PASSPHRASE) {
        return if p.is_empty() {
            Err(Error::EmptyPassphrase)
        } else {
            Ok(p.into())
        };
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
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .open(p)
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

/// Private (0700) scratch dir with a random name, removed on drop (including error paths).
fn scratch_dir(root: &Path) -> io::Result<tempfile::TempDir> {
    tempfile::Builder::new()
        .prefix(TMP_PREFIX)
        .permissions(fs::Permissions::from_mode(PRIVATE_DIR_MODE))
        .tempdir_in(root)
}

fn main() {
    let cli = Cli::parse();
    let res = match &cli.cmd {
        Cmd::Push(a) => push(&cli.common, a),
        Cmd::Pull(a) => pull(&cli.common, a),
    };
    match res {
        Ok(()) => {}
        Err(Error::Cli(e)) => e.exit(),
        Err(e) => {
            eprintln!("{PROGRAM}: {e}");
            std::process::exit(1);
        }
    }
}
