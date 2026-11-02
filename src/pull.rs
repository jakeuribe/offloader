use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::cli::{Common, PullArgs};
use crate::crypto::{decrypt, passphrase};
use crate::error::{Error, R};
use crate::fsutil::scratch_dir;
use crate::method::Method;
use crate::record::Record;
use crate::vocab::{BLOB_NAME, PARTIAL_PREFIX, PRIVATE_FILE_MODE};

/// Decrypt the record, fetch + decrypt the blob, restore it in place, optionally purge.
pub fn pull(common: &Common, args: &PullArgs) -> R<()> {
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
