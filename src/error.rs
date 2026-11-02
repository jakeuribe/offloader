use std::io;
use std::path::PathBuf;
use std::process::ExitStatus;

use crate::vocab::flag;

#[derive(Debug, thiserror::Error)]
pub enum Error {
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
    #[error(
        "--{purge} with the shell method needs --{rm} (at push or pull)",
        purge = flag::PURGE,
        rm = flag::RM
    )]
    NoRemover,
    #[error("file restored, but remote copy {id} was not removed: {cause}")]
    RemoteKept { id: String, cause: Box<Error> },
    #[error("bad record: {0}")]
    Record(&'static str),
    /// Usage errors raised after parsing; `main` exits through clap so they look like its own.
    #[error(transparent)]
    Cli(clap::Error),
}

pub type R<T> = Result<T, Error>;
