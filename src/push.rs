use age::secrecy::ExposeSecret;
use std::fs::{self, File};
use std::io::{self, BufReader, Write};
use std::os::unix::fs::MetadataExt;

use crate::cli::{Common, PushArgs};
use crate::crypto::{decrypt, passphrase, random_id};
use crate::error::{At, Error, R};
use crate::fsutil::{human, private_file, same, scratch_dir};
use crate::record::{Meta, Record};
use crate::vocab::{BLOB_NAME, PROGRAM, VERIFY_NAME};

/// Encrypt, upload, verify, write the record, and only then delete the original.
pub fn push(common: &Common, args: &PushArgs) -> R<()> {
    let file = &args.file;
    // metadata() follows symlinks: pushing one would upload the target but delete only the link.
    if fs::symlink_metadata(file).at(file)?.is_symlink() {
        return Err(Error::IsSymlink(file.clone()));
    }
    let file_meta = fs::metadata(file).at(file)?;
    if file_meta.is_dir() {
        return Err(Error::IsDirectory(file.clone()));
    }
    if common.is_record(file) {
        return Err(Error::IsRecord {
            path: file.clone(),
            ext: common.ext.clone(),
        });
    }
    if !file_meta.is_file() {
        return Err(Error::NotRegularFile(file.clone()));
    }
    let record_path = common.record_path(file);
    if record_path.exists() {
        return Err(Error::Exists(record_path));
    }
    let method = args.method()?;
    if file_meta.nlink() > 1 {
        eprintln!(
            "{PROGRAM}: warning: {} has {} hard links; no space is freed until the others go",
            file.display(),
            file_meta.nlink()
        );
    }
    let pass = passphrase(true)?;
    let rec = Record {
        id: random_id()?,
        key: age::x25519::Identity::generate(),
        method,
        meta: Meta::of(&file_meta),
    };
    let root = common.scratch_root(file);
    let tmp = scratch_dir(&root).at(&root)?;

    let blob = tmp.path().join(BLOB_NAME);
    let recipient = rec.key.to_public();
    let mut w = age::Encryptor::with_recipients(std::iter::once(&recipient as _))?
        .wrap_output(private_file(&blob).at(&blob)?)?;
    io::copy(&mut File::open(file).at(file)?, &mut w)?;
    w.finish()?.sync_all()?;

    rec.method.put(&blob, &rec.id)?;
    // Uploaded; free the scratch space before verify fetches its own copy.
    fs::remove_file(&blob).at(&blob)?;

    // Everything between the upload and deleting the original. If any of it fails no
    // usable record points at the upload, so the upload is removed again below.
    let commit = || -> R<()> {
        if !args.no_verify {
            let back = tmp.path().join(VERIFY_NAME);
            rec.method.get(&back, &rec.id)?;
            if !same(
                &mut decrypt(&back, &rec.key)?,
                &mut BufReader::new(File::open(file).at(file)?),
            )? {
                return Err(Error::VerifyMismatch);
            }
        }
        // The copy was made from the file as it was; don't delete one that has moved on.
        let now = fs::metadata(file).at(file)?;
        if now.len() != file_meta.len() || now.modified().ok() != file_meta.modified().ok() {
            return Err(Error::Changed(file.clone()));
        }
        // Record durable on disk before the original goes away. create_new: an existing
        // record makes this fail before anything of ours exists to clean up.
        let out = private_file(&record_path).at(&record_path)?;
        let written = (|| -> R<()> {
            let mut w = age::Encryptor::with_user_passphrase(pass).wrap_output(out)?;
            w.write_all(rec.encode().expose_secret().as_bytes())?;
            Ok(w.finish()?.sync_all()?)
        })();
        if written.is_err() {
            let _ = fs::remove_file(&record_path);
        }
        written
    };
    if let Err(e) = commit() {
        match rec.method.remove(&rec.id) {
            Ok(()) => eprintln!("{PROGRAM}: push failed; removed remote copy {}", rec.id),
            Err(_) => eprintln!(
                "{PROGRAM}: push failed; remote copy {} was left behind",
                rec.id
            ),
        }
        return Err(e);
    }
    fs::remove_file(file).at(file)?;
    println!(
        "offloaded {} ({}) -> {} (id {})",
        file.display(),
        human(file_meta.len()),
        record_path.display(),
        rec.id
    );
    Ok(())
}
