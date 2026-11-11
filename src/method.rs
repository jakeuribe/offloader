//! Transports: how an encrypted blob gets out to the remote and back.

use clap::ValueEnum;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{At, Error, R};
use crate::fsutil::private_file;
use crate::vocab::{METHOD_DIR, METHOD_SHELL, SHELL, SHELL_FLAG, flag};

#[derive(Clone, Copy, ValueEnum)]
pub enum MethodKind {
    /// Copy into a local directory (NAS mount, USB, …)
    #[value(name = METHOD_DIR)]
    Dir,
    /// Run user-supplied put/get/rm commands
    #[value(name = METHOD_SHELL)]
    Shell,
}
impl MethodKind {
    pub fn name(self) -> String {
        self.to_possible_value()
            .expect("no skipped variants")
            .get_name()
            .to_owned()
    }
    pub fn parse(s: &str) -> Option<Self> {
        <Self as ValueEnum>::from_str(s, false).ok()
    }
}

/// How a blob gets out and back. Stored in the record.
pub enum Method {
    Dir(PathBuf),
    Shell {
        put: String,
        get: String,
        rm: Option<String>,
    },
}

/// Env vars exposed to shell commands.
#[derive(Clone, Copy)]
pub enum ShellVar {
    Src,
    Dst,
    Id,
}
impl ShellVar {
    pub fn name(self) -> &'static str {
        match self {
            Self::Src => "SRC",
            Self::Dst => "DST",
            Self::Id => "ID",
        }
    }
}

impl Method {
    pub fn kind(&self) -> MethodKind {
        match self {
            Self::Dir(_) => MethodKind::Dir,
            Self::Shell { .. } => MethodKind::Shell,
        }
    }

    pub fn put(&self, src: &Path, id: &str) -> R<()> {
        match self {
            Self::Dir(d) => {
                let to = d.join(id);
                let mut out = private_file(&to).at(&to)?;
                let copied = File::open(src)
                    .and_then(|mut f| io::copy(&mut f, &mut out))
                    .and_then(|_| out.sync_all());
                if copied.is_err() {
                    // We created it just above; don't leave half a blob behind.
                    let _ = fs::remove_file(&to);
                }
                copied.at(&to)
            }
            Self::Shell { put, .. } => sh(
                flag::PUT,
                put,
                &[
                    (ShellVar::Src, src.as_os_str()),
                    (ShellVar::Id, id.as_ref()),
                ],
            ),
        }
    }

    pub fn get(&self, dst: &Path, id: &str) -> R<()> {
        match self {
            Self::Dir(d) => {
                let from = d.join(id);
                io::copy(
                    &mut File::open(&from).at(&from)?,
                    &mut private_file(dst).at(dst)?,
                )?;
                Ok(())
            }
            Self::Shell { get, .. } => sh(
                flag::GET,
                get,
                &[
                    (ShellVar::Dst, dst.as_os_str()),
                    (ShellVar::Id, id.as_ref()),
                ],
            ),
        }
    }

    pub fn can_remove(&self) -> bool {
        matches!(self, Self::Dir(_) | Self::Shell { rm: Some(_), .. })
    }

    pub fn remove(&self, id: &str) -> R<()> {
        match self {
            Self::Dir(d) => {
                let p = d.join(id);
                match fs::remove_file(&p) {
                    // Already gone is the goal; lets `rm` finish a half-done removal. Only if
                    // the directory is there: a moved or deleted one hasn't lost the blob.
                    // (An empty mount point left by an unmounted disk still looks "gone".)
                    Err(e) if e.kind() == io::ErrorKind::NotFound && d.is_dir() => Ok(()),
                    r => r.at(&p),
                }
            }
            Self::Shell { rm: Some(rm), .. } => sh(flag::RM, rm, &[(ShellVar::Id, id.as_ref())]),
            Self::Shell { rm: None, .. } => Err(Error::NoRemover),
        }
    }
}

/// Values go in via env, never spliced into the command string, so they can't inject shell.
fn sh(step: &'static str, cmd: &str, env: &[(ShellVar, &OsStr)]) -> R<()> {
    let status = Command::new(SHELL)
        .arg(SHELL_FLAG)
        .arg(cmd)
        .envs(env.iter().map(|(k, v)| (k.name(), v)))
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::CommandFailed {
            step,
            cmd: cmd.into(),
            status,
        })
    }
}
