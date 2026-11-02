use age::secrecy::ExposeSecret;
use std::fs::{self, File};
use std::io::{self, BufReader, Write};

use crate::cli::{Common, PushArgs};
use crate::crypto::{decrypt, passphrase, random_id};
use crate::error::{Error, R};
use crate::fsutil::{private_file, same, scratch_dir};
use crate::record::{Meta, Record};
use crate::vocab::{BLOB_NAME, VERIFY_NAME};

/// Encrypt, upload, verify, write the record, and only then delete the original.
pub fn push(common: &Common, args: &PushArgs) -> R<()> {
    let file = &args.file;
    let file_meta = fs::metadata(file)?;
    if !file_meta.is_file() {
        return Err(Error::NotRegularFile(file.clone()));
    }
    let record_path = common.record_path(file);
    if record_path.exists() {
        return Err(Error::Exists(record_path));
    }
    let method = args.method()?;
    let pass = passphrase(true)?;
    let rec = Record {
        id: random_id()?,
        key: age::x25519::Identity::generate(),
        method,
        meta: Meta::of(&file_meta),
    };
    let tmp = scratch_dir(&common.tmp)?;

    let blob = tmp.path().join(BLOB_NAME);
    let recipient = rec.key.to_public();
    let mut w = age::Encryptor::with_recipients(std::iter::once(&recipient as _))?
        .wrap_output(private_file(&blob)?)?;
    io::copy(&mut File::open(file)?, &mut w)?;
    w.finish()?.sync_all()?;

    rec.method.put(&blob, &rec.id)?;

    if !args.no_verify {
        let back = tmp.path().join(VERIFY_NAME);
        rec.method.get(&back, &rec.id)?;
        if !same(
            &mut decrypt(&back, &rec.key)?,
            &mut BufReader::new(File::open(file)?),
        )? {
            return Err(Error::VerifyMismatch);
        }
    }

    // Record durable on disk before the original goes away.
    let mut w =
        age::Encryptor::with_user_passphrase(pass).wrap_output(private_file(&record_path)?)?;
    w.write_all(rec.encode().expose_secret().as_bytes())?;
    w.finish()?.sync_all()?;
    fs::remove_file(file)?;
    println!(
        "offloaded {} -> {} (id {})",
        file.display(),
        record_path.display(),
        rec.id
    );
    Ok(())
}
