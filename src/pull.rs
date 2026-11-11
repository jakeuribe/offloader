use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::cli::{Common, PullArgs, RmArgs};
use crate::crypto::{decrypt, passphrase};
use crate::error::{At, Error, R};
use crate::fsutil::{parent, scratch_dir};
use crate::method::Method;
use crate::record::Record;
use crate::vocab::{BLOB_NAME, METHOD_DIR, METHOD_SHELL, PARTIAL_PREFIX, PRIVATE_FILE_MODE, flag};

/// Decrypt the record, fetch + decrypt the blob, restore it in place, optionally purge.
pub fn pull(common: &Common, args: &PullArgs) -> R<()> {
    let record_path = &resolve(common, &args.record)?;
    let purge = args.purge && !args.no_purge;
    let out = record_path.with_extension("");
    if out.exists() {
        return Err(Error::Exists(out));
    }
    let mut rec = load(record_path)?;
    redirect(
        &mut rec.method,
        args.dir.as_ref(),
        args.get.as_ref(),
        args.rm.as_ref(),
    )?;
    // Fail before touching anything if purge can't be honored.
    if purge && !rec.method.can_remove() {
        return Err(Error::NoRemover);
    }

    let root = common.scratch_root(record_path);
    let tmp = scratch_dir(&root).at(&root)?;
    let blob = tmp.path().join(BLOB_NAME);
    rec.method.get(&blob, &rec.id)?;

    // AEAD fails on any tampering/truncation, so only authentic plaintext gets persisted.
    // The temp file (0600) is deleted on drop if anything fails before that.
    let dir = parent(&out);
    let mut w = tempfile::Builder::new()
        .prefix(PARTIAL_PREFIX)
        .permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))
        .tempfile_in(dir)
        .at(dir)?;
    io::copy(&mut decrypt(&blob, &rec.key)?, &mut w)?;
    rec.meta.apply(w.as_file())?;
    w.as_file().sync_all()?;
    // No-clobber: if something created `out` since the check above, fail instead of overwriting.
    w.persist_noclobber(&out)
        .map_err(|e| match e.error.kind() {
            io::ErrorKind::AlreadyExists => Error::Exists(out.clone()),
            _ => e.error.into(),
        })?;
    println!("restored {}", out.display());
    // Only after the plaintext is safely in place. The record is the only handle on the
    // remote copy, so it outlives a failed purge (`rm` retries it).
    if purge {
        rec.method.remove(&rec.id).map_err(|e| Error::RemoteKept {
            id: rec.id.clone(),
            record: record_path.clone(),
            cause: Box::new(e),
        })?;
        println!("removed remote copy {}", rec.id);
    }
    fs::remove_file(record_path).at(record_path)
}

/// Delete the remote copy, then the record. Refuses while the record is the only way
/// back to the data, unless forced.
pub fn rm(common: &Common, args: &RmArgs) -> R<()> {
    let record_path = &resolve(common, &args.record)?;
    let out = record_path.with_extension("");
    // Cheap check first, so the obvious mistake fails before the passphrase prompt.
    if !args.force && !out.exists() {
        return Err(Error::NotRestored(out));
    }
    let mut rec = load(record_path)?;
    // Some unrelated file that happens to have the name doesn't count as restored.
    if !args.force && !fs::metadata(&out).is_ok_and(|m| rec.meta.restored_as(&m)) {
        return Err(Error::NotRestored(out));
    }
    redirect(&mut rec.method, None, None, args.rm.as_ref())?;
    rec.method.remove(&rec.id)?;
    println!("removed remote copy {}", rec.id);
    fs::remove_file(record_path).at(record_path)
}

/// The record a user argument names. Accepts the original file name too:
/// `big.iso` finds `big.iso.<ext>`. Checked here so a typo fails before the passphrase prompt.
fn resolve(common: &Common, arg: &Path) -> R<PathBuf> {
    let record_path = if common.is_record(arg) {
        arg.to_owned()
    } else {
        let candidate = common.record_path(arg);
        if !candidate.exists() && arg.exists() {
            return Err(Error::WrongExtension {
                path: arg.to_owned(),
                ext: common.ext.clone(),
            });
        }
        candidate
    };
    fs::metadata(&record_path).at(&record_path)?;
    Ok(record_path)
}

fn load(record_path: &Path) -> R<Record> {
    let pass = passphrase(false)?;
    let mut body = String::new();
    age::Decryptor::new(BufReader::new(File::open(record_path).at(record_path)?))?
        .decrypt(std::iter::once(&age::scrypt::Identity::new(pass) as _))?
        .read_to_string(&mut body)?;
    Record::decode(&body)
}

/// Point a record somewhere else for this run (the remote moved, or needs another command).
fn redirect(
    method: &mut Method,
    dir: Option<&PathBuf>,
    get: Option<&String>,
    rm: Option<&String>,
) -> R<()> {
    let wrong = |flag, method| Err(Error::Override { flag, method });
    match method {
        Method::Dir(_) if get.is_some() => wrong(flag::GET, METHOD_DIR),
        Method::Shell { .. } if dir.is_some() => wrong(flag::DIR, METHOD_SHELL),
        Method::Dir(d) => {
            // `rm` may come from the env of a shell-method setup; it means nothing here.
            if let Some(new) = dir {
                d.clone_from(new);
            }
            Ok(())
        }
        Method::Shell { get: g, rm: r, .. } => {
            if let Some(new) = get {
                g.clone_from(new);
            }
            if let Some(new) = rm {
                *r = Some(new.clone());
            }
            Ok(())
        }
    }
}
