# offloader

Moves a file somewhere else and leaves an encrypted `<file>.offload` record in its place. The record holds what's needed to get the file back.

## Install

Each tagged [release](https://github.com/jakeuribe/offloader/releases) has prebuilt binaries for Linux (x86_64 glibc and static musl, aarch64) and macOS (Apple silicon and Intel), with `.sha256` checksums:

```sh
tar -xzf offloader-v*-x86_64-unknown-linux-gnu.tar.gz
install -m 755 offloader ~/.local/bin/
```

Or build from source with `cargo install --path .` (Rust 1.88+).

## Usage

```sh
offloader push bigfile.iso            # encrypt, upload, verify, delete local
offloader pull bigfile.iso.offload    # fetch, decrypt, restore (`pull bigfile.iso` works too)
offloader rm   bigfile.iso.offload    # after a failed --purge: delete the remote copy and the record
```

The remote only sees ciphertext and a random id. The record is encrypted with your passphrase (`$OFFLOADER_PASSPHRASE`, or a prompt). Lose either the record or the passphrase and the file is gone.

## Methods

**`shell`** (default) runs your commands. Paths arrive as `$SRC`, `$DST` and `$ID`, so filenames can't inject shell:

```sh
export OFFLOADER_PUT='scp -q "$SRC" me@host:offload/$ID'
export OFFLOADER_GET='scp -q me@host:offload/$ID "$DST"'
export OFFLOADER_RM='ssh me@host rm offload/$ID'
```

**`dir`** copies into a local directory: `--method dir --dir /mnt/nas/offload` (or `-m dir -d /mnt/nas/offload`).

## Flags

The `push` flags, `--purge`, `--ext` and `--tmp` have an env fallback (`--put` → `OFFLOADER_PUT`, and so on). Flags that override what a record stored (`--rm`/`--get`/`--dir` on `pull` and `rm`) must be given explicitly, as must `--no-purge` and `--force`.

| Flag | Meaning |
|---|---|
| `--method dir\|shell` | transport |
| `--dir PATH` | target for `dir` |
| `--put` / `--get` / `--rm CMD` | shell commands |
| `pull --get CMD` / `pull --dir PATH` | fetch from somewhere other than the record says (the remote moved) |
| `--purge` / `--no-purge` | delete the remote copy after pull (`OFFLOADER_PURGE=1` makes it the default); `--no-purge` always wins |
| `--no-verify` | skip the round-trip check on push |
| `rm --force` | remove the remote copy even though the restored file isn't there (or was changed since) |
| `--ext EXT` | record extension |
| `--tmp PATH` | scratch dir; defaults to the file's own directory |

## Notes

- Push deletes the original only after it has re-downloaded and verified the copy and the record is on disk.
- If that verification fails, push removes the upload again (when it knows how) so nothing is orphaned.
- Push needs free space the size of the file next to it for the encrypted copy, and pull needs twice that (the fetched copy plus the restored file); `--tmp` moves the scratch copy elsewhere. A killed run can leave a `.offloader-tmp-*` directory of ciphertext behind, which is safe to delete. A plain `pull` leaves the remote copy in place and deletes the record; use `--purge` to remove both.
- If `--purge` can't remove the remote copy, the file is still restored and the record is kept so `offloader rm` can retry.
- Symlinks are refused, and hard-linked files get a warning: neither frees space the way you'd expect.
- Pull restores the mode and timestamps but not the owner.
- One file at a time; `tar` directories first. Unix only.
- Run the tests with `./test.sh`.

## License

Apache-2.0. See [LICENSE](LICENSE).
