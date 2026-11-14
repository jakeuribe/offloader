//! offloader: move a file elsewhere, leave an encrypted retrieval record in its place.
//!
//! The file is age/X25519-encrypted with a fresh key before leaving the machine; the
//! record (key, id, method, file metadata) is age/scrypt-encrypted with your passphrase.
//! The CLI surface lives in `cli.rs`; `offloader --help` documents it.
#![doc = ""]
#![doc = include_str!("../docs/CLI.md")]

mod cli;
mod crypto;
mod error;
mod fsutil;
mod method;
mod pull;
mod push;
mod record;
mod vocab;

use clap::Parser;

use cli::{Cli, Cmd};
use error::Error;
use vocab::PROGRAM;

fn main() {
    let cli = Cli::parse();
    let res = match &cli.cmd {
        Cmd::Push(a) => push::push(&cli.common, a),
        Cmd::Pull(a) => pull::pull(&cli.common, a),
        Cmd::Rm(a) => pull::rm(&cli.common, a),
    };
    match res {
        Ok(()) => {}
        Err(Error::Cli(e)) => e.exit(),
        Err(e) => {
            eprintln!("{PROGRAM}: {e}");
            std::process::exit(1);
        }
    }
}
