use age::secrecy::SecretString;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use crate::error::{Error, R};
use crate::vocab::{ID_BYTES, PROMPT_CONFIRM, PROMPT_PASS, env};

/// Streaming reader over a blob encrypted to `key`. Fails on any tampering.
pub fn decrypt(p: &Path, key: &age::x25519::Identity) -> R<impl Read> {
    Ok(age::Decryptor::new(BufReader::new(File::open(p)?))?.decrypt(std::iter::once(key as _))?)
}

/// From `$OFFLOADER_PASSPHRASE`, else prompted (twice when `confirm`).
pub fn passphrase(confirm: bool) -> R<SecretString> {
    if let Ok(p) = std::env::var(env::PASSPHRASE) {
        return if p.is_empty() {
            Err(Error::EmptyPassphrase)
        } else {
            Ok(p.into())
        };
    }
    let p = rpassword::prompt_password(PROMPT_PASS).map_err(Error::NoPassphrase)?;
    if p.is_empty() {
        return Err(Error::EmptyPassphrase);
    }
    if confirm && rpassword::prompt_password(PROMPT_CONFIRM).map_err(Error::NoPassphrase)? != p {
        return Err(Error::PassphraseMismatch);
    }
    Ok(p.into())
}

/// Random hex object id; the only name the remote ever sees.
pub fn random_id() -> R<String> {
    let mut b = [0u8; ID_BYTES];
    getrandom::fill(&mut b).map_err(|e| Error::Rng(e.to_string()))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}
