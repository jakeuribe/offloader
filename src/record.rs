//! The decrypted record: `key=value` lines holding everything needed to retrieve a file.

use age::secrecy::{ExposeSecret, SecretString};
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::{Error, R};
use crate::method::{Method, MethodKind};
use crate::vocab::{ID_BYTES, MODE_MASK, MODE_RADIX, RECORD_MAGIC, RECORD_SEP};

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

pub struct Record {
    pub id: String,
    pub key: age::x25519::Identity,
    pub method: Method,
    pub meta: Meta,
}

/// Original file metadata, restored on pull. Optional so older records still decode
/// (missing fields leave the restored file at the private defaults).
/// Owner isn't stored: only root could restore it, and pull runs as the user.
#[derive(Default)]
pub struct Meta {
    mode: Option<u32>,
    mtime: Option<SystemTime>,
    atime: Option<SystemTime>,
}
impl Meta {
    pub fn of(m: &fs::Metadata) -> Self {
        Self {
            mode: Some(m.permissions().mode() & MODE_MASK),
            mtime: m.modified().ok(),
            atime: m.accessed().ok(),
        }
    }

    /// Whether `m` looks like the file pull restored from this record: a regular file
    /// carrying the recorded mtime (pull sets it exactly; 2s slack for coarse filesystems).
    /// ponytail: mtime only, the record holds no size or hash; add one if this proves weak.
    pub fn restored_as(&self, m: &fs::Metadata) -> bool {
        let (Some(want), Ok(got)) = (self.mtime, m.modified()) else {
            return false;
        };
        m.is_file() && (time_to_nanos(want) - time_to_nanos(got)).abs() <= 2_000_000_000
    }

    /// Apply to an open file; call after the last write so mtime sticks.
    pub fn apply(&self, f: &File) -> io::Result<()> {
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
    pub fn encode(&self) -> SecretString {
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

    pub fn decode(body: &str) -> R<Self> {
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
