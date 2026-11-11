use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use crate::vocab::{PROGRAM, env, flag};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("{}: {source}", .path.display())]
    Path { path: PathBuf, source: io::Error },
    #[error("encrypt: {0}")]
    Encrypt(#[from] age::EncryptError),
    #[error("decrypt: {0}")]
    Decrypt(#[from] age::DecryptError),
    #[error("{} already exists", .0.display())]
    Exists(PathBuf),
    #[error("{} is not a regular file", .0.display())]
    NotRegularFile(PathBuf),
    #[error("{} is a symlink; push its target instead", .0.display())]
    IsSymlink(PathBuf),
    #[error("{} is a directory; tar it first", .0.display())]
    IsDirectory(PathBuf),
    #[error(
        "{} is already a .{ext} record; refusing to offload it (--{} changes the extension)",
        .path.display(),
        flag::EXT
    )]
    IsRecord { path: PathBuf, ext: String },
    #[error(
        "{}: expected a .{ext} file (--{} changes the extension)",
        .path.display(),
        flag::EXT
    )]
    WrongExtension { path: PathBuf, ext: String },
    #[error("no passphrase: set ${var} or run in a terminal ({0})", var = env::PASSPHRASE)]
    NoPassphrase(io::Error),
    #[error("--{flag} does not apply: this record uses the {method} method")]
    Override {
        flag: &'static str,
        method: &'static str,
    },
    #[error(
        "{} is missing or doesn't match what this record restored (modified since?); removing the remote copy could destroy the only copy (--{} to do it anyway)",
        .0.display(),
        flag::FORCE
    )]
    NotRestored(PathBuf),
    #[error("empty passphrase")]
    EmptyPassphrase,
    #[error("passphrases differ")]
    PassphraseMismatch,
    #[error("rng: {0}")]
    Rng(String),
    #[error("{step} command failed ({status}): {cmd}")]
    CommandFailed {
        step: &'static str,
        cmd: String,
        status: ExitStatus,
    },
    #[error("verify failed: fetched copy differs; original untouched")]
    VerifyMismatch,
    #[error("{} changed while it was being offloaded; original untouched", .0.display())]
    Changed(PathBuf),
    #[error(
        "removing the remote copy with the shell method needs --{rm} (now or at push)",
        rm = flag::RM
    )]
    NoRemover,
    #[error(
        "file restored, but remote copy {id} was not removed: {cause}\n\
         record kept; retry with `{PROGRAM} rm {}`",
        .record.display()
    )]
    RemoteKept {
        id: String,
        record: PathBuf,
        cause: Box<Error>,
    },
    #[error("bad record: {0}")]
    Record(&'static str),
    /// Usage errors raised after parsing; `main` exits through clap so they look like its own.
    #[error(transparent)]
    Cli(clap::Error),
}

pub type R<T> = Result<T, Error>;

/// Name the file an I/O error happened on.
pub trait At<T> {
    fn at(self, path: &Path) -> R<T>;
}
impl<T> At<T> for io::Result<T> {
    fn at(self, path: &Path) -> R<T> {
        self.map_err(|source| Error::Path {
            path: path.into(),
            source,
        })
    }
}
