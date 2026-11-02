# offloader

Moves a file somewhere else and leaves an encrypted `<file>.offload` record in its place. The record holds what's needed to get the file back.

```sh
cargo install --path .
offloader push bigfile.iso            # encrypt, upload, verify, delete local
offloader pull bigfile.iso.offload    # fetch, decrypt, restore
```

The remote only sees ciphertext and a random id. The record is encrypted with your passphrase (`$OFFLOADER_PASSPHRASE`, or a prompt). Lose either the record or the passphrase and the file is gone.

## Methods

**`shell`** (default) runs your commands. Paths arrive as `$SRC`, `$DST` and `$ID`, so filenames can't inject shell:

```sh
export OFFLOADER_PUT='scp -q "$SRC" me@host:offload/$ID'
export OFFLOADER_GET='scp -q me@host:offload/$ID "$DST"'
export OFFLOADER_RM='ssh me@host rm offload/$ID'
```

**`dir`** copies into a local directory: `--method dir --dir /mnt/nas/offload`.

## Flags

Every flag has an env fallback (`--put` → `OFFLOADER_PUT`, and so on).

| Flag | Meaning |
|---|---|
| `--method dir\|shell` | transport |
| `--dir PATH` | target for `dir` |
| `--put` / `--get` / `--rm CMD` | shell commands |
| `--purge` / `--no-purge` | delete the remote copy after pull (`OFFLOADER_PURGE=1` makes it the default); `--no-purge` always wins |
| `--no-verify` | skip the round-trip check on push |
| `--ext EXT`, `--tmp PATH` | record extension, scratch dir |

## Notes

- Push deletes the original only after it has re-downloaded and verified the copy and the record is on disk.
- Pull restores the mode and timestamps but not the owner.
- One file at a time; `tar` directories first. Unix only.
- Run the tests with `./test.sh`.

## License

Apache-2.0. See [LICENSE](LICENSE).
