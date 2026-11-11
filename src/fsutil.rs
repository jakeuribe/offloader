use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::vocab::{COMPARE_BUF, PRIVATE_DIR_MODE, PRIVATE_FILE_MODE, TMP_PREFIX};

/// New 0600 file; fails if `p` already exists.
pub fn private_file(p: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .open(p)
}

/// Private (0700) scratch dir with a random name, removed on drop (including error paths).
pub fn scratch_dir(root: &Path) -> io::Result<tempfile::TempDir> {
    tempfile::Builder::new()
        .prefix(TMP_PREFIX)
        .permissions(fs::Permissions::from_mode(PRIVATE_DIR_MODE))
        .tempdir_in(root)
}

/// True if both readers yield identical bytes.
pub fn same(a: &mut impl Read, b: &mut impl Read) -> io::Result<bool> {
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

/// Fill `buf` unless EOF comes first; returns bytes read.
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

/// Directory containing `p` (`.` for a bare file name).
pub fn parent(p: &Path) -> &Path {
    p.parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

/// Byte count for humans: `512 B`, `1.5 GiB`.
pub fn human(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let (mut v, mut i) = (n as f64, 0);
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}
