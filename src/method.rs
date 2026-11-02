//! Transports: how an encrypted blob gets out to the remote and back.

use clap::ValueEnum;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{Error, R};
use crate::fsutil::private_file;
use crate::vocab::{METHOD_DIR, METHOD_SHELL, SHELL, SHELL_FLAG};

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

    pub fn get(&self, dst: &Path, id: &str) -> R<()> {
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

    pub fn can_remove(&self) -> bool {
        matches!(self, Self::Dir(_) | Self::Shell { rm: Some(_), .. })
    }

    pub fn remove(&self, id: &str) -> R<()> {
        match self {
            Self::Dir(d) => Ok(fs::remove_file(d.join(id))?),
            Self::Shell { rm: Some(rm), .. } => sh(rm, &[(ShellVar::Id, id.as_ref())]),
            Self::Shell { rm: None, .. } => Err(Error::NoRemover),
        }
    }
}

/// Values go in via env, never spliced into the command string, so they can't inject shell.
fn sh(cmd: &str, env: &[(ShellVar, &OsStr)]) -> R<()> {
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
