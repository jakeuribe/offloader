//! Command-line surface. `offloader --help` is generated from this file.

use clap::builder::BoolishValueParser;
use clap::error::ErrorKind;
use clap::{ArgAction, Args, CommandFactory, Parser, Subcommand};
use std::path::{Path, PathBuf};

use crate::error::{Error, R};
use crate::method::{Method, MethodKind, ShellVar};
use crate::vocab::*;

#[derive(Parser)]
#[command(name = PROGRAM, version, about, after_help = after_help())]
pub struct Cli {
    #[command(flatten)]
    pub common: Common,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Args)]
pub struct Common {
    /// Record file extension
    #[arg(
        long = flag::EXT,
        env = env::EXT,
        default_value = DEFAULT_EXT,
        value_parser = parse_ext,
        global = true
    )]
    pub ext: String,
    /// Root for private scratch dirs
    #[arg(
        long = flag::TMP,
        env = env::TMP,
        global = true,
        default_value_os_t = std::env::temp_dir()
    )]
    pub tmp: PathBuf,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Encrypt + upload FILE, verify, then replace it with FILE.<ext>
    Push(PushArgs),
    /// Fetch + decrypt the file a record points to, restoring it in place
    Pull(PullArgs),
}

#[derive(Args)]
pub struct PushArgs {
    pub file: PathBuf,
    /// How the blob leaves the machine
    #[arg(
        id = flag::METHOD,
        long = flag::METHOD,
        env = env::METHOD,
        value_enum,
        default_value_t = MethodKind::Shell
    )]
    pub method: MethodKind,
    /// Target directory (absolute) for the dir method
    #[arg(
        long = flag::DIR,
        env = env::DIR,
        value_parser = parse_dir,
        required_if_eq(flag::METHOD, METHOD_DIR)
    )]
    pub dir: Option<PathBuf>,
    /// Upload command (shell method)
    #[arg(long = flag::PUT, env = env::PUT, value_parser = parse_cmd)]
    pub put: Option<String>,
    /// Download command (shell method; stored in the record)
    #[arg(long = flag::GET, env = env::GET, value_parser = parse_cmd)]
    pub get: Option<String>,
    /// Remove command for later purges (shell method; stored in the record)
    #[arg(long = flag::RM, env = env::RM, value_parser = parse_cmd)]
    pub rm: Option<String>,
    /// Skip downloading the copy back to verify it before deleting the original
    #[arg(
        long = flag::NO_VERIFY,
        env = env::NO_VERIFY,
        action = ArgAction::SetTrue,
        value_parser = BoolishValueParser::new()
    )]
    pub no_verify: bool,
}

#[derive(Args)]
pub struct PullArgs {
    pub record: PathBuf,
    /// Delete the remote copy after a successful restore
    #[arg(
        long = flag::PURGE,
        env = env::PURGE,
        action = ArgAction::SetTrue,
        value_parser = BoolishValueParser::new()
    )]
    pub purge: bool,
    /// Keep the remote copy; always wins over --purge / $OFFLOADER_PURGE
    #[arg(long = flag::NO_PURGE, action = ArgAction::SetTrue)]
    pub no_purge: bool,
    /// Remove command, overriding the one stored in the record (shell method)
    #[arg(long = flag::RM, env = env::RM, value_parser = parse_cmd)]
    pub rm: Option<String>,
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
        "Shell commands run under `{SHELL} {SHELL_FLAG}` with ${}, ${}, ${} in the env.\n\
         Passphrase: ${} or prompt.",
        ShellVar::Src.name(),
        ShellVar::Dst.name(),
        ShellVar::Id.name(),
        env::PASSPHRASE
    )
}

impl Common {
    pub fn record_path(&self, file: &Path) -> PathBuf {
        let mut s = file.as_os_str().to_owned();
        s.push(format!(".{}", self.ext));
        s.into()
    }
}

impl PushArgs {
    /// `--dir` is enforced by clap's `required_if_eq` (dir is never the default method).
    /// `--put`/`--get` are checked here: `required_if_eq` ignores default values, and shell
    /// is the default. Errors go through clap so they look and exit like its own.
    pub fn method(&self) -> R<Method> {
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
