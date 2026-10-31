# offloader

Move a file somewhere else and leave a small encrypted record in its place. The
record holds everything needed to get the file back.

``` $ offloader push bigfile.iso offloaded bigfile.iso -> bigfile.iso.offload
(id 3f9c…) $ offloader pull bigfile.iso.offload restored bigfile.iso ```

The file is encrypted before it leaves the machine, so the remote only ever
stores ciphertext. The `.offload` record is encrypted with your passphrase.

## Install

```sh cargo install --path .        # installs to ~/.cargo/bin/offloader ```

Unix only (Linux, macOS).

## Methods

A method is how the encrypted blob gets to the remote and back.

| Method | What it does | Needs | |---|---|---| | `shell` (default) | Runs your
commands under `sh -c` | `--put`, `--get`, optionally `--rm` | | `dir` | Copies
into a local directory, e.g. a NAS or USB mount | `--dir` (absolute path) |

Shell commands get their values through environment variables. Nothing is
pasted into the command text, so filenames can't inject shell.

| Var | Set for | Meaning | |---|---|---| | `$SRC` | put | encrypted blob to
upload | | `$DST` | get | path to download the blob to | | `$ID` | put, get, rm
| random 32-hex-char object id |

Keep the commands in single quotes so the variables are expanded by offloader,
not by your shell.

### Examples

**SSH host** ```sh ssh me@host 'mkdir -p ~/offload && chmod 700 ~/offload'
export OFFLOADER_PUT='scp -q "$SRC" me@host:offload/$ID' export
OFFLOADER_GET='scp -q me@host:offload/$ID "$DST"' export OFFLOADER_RM='ssh
me@host rm offload/$ID' ```

**rclone (S3, GDrive, B2, …)** ```sh export OFFLOADER_PUT='rclone copyto "$SRC"
remote:bucket/$ID' export OFFLOADER_GET='rclone copyto remote:bucket/$ID
"$DST"' export OFFLOADER_RM='rclone deletefile remote:bucket/$ID' ```

**Mounted directory** ```sh offloader push file --method dir --dir
/mnt/nas/offload ```

## What push and pull do

**push `<file>`**
1. Encrypts the file to a fresh X25519 key (age).
2. Uploads the blob.
3. Verifies by downloading it back, decrypting it and comparing it byte for
   byte with the original. Skip this with `--no-verify`.
4. Writes `<file>.offload` (the id, the key, the get/rm commands or
   directory, and the file's permission bits and mtime/atime, encrypted with
   your passphrase) and syncs it to disk.
5. Deletes the original, and only then.

If any step fails, the original is left untouched.

**pull `<file>.offload`**
1. Decrypts the record.
2. Downloads the blob and decrypts it to `<file>-partial`. Decryption is
   authenticated, so any tampering or truncation fails here.
3. Restores the original permission bits (including setuid/setgid/sticky) and
   mtime/atime, then renames it to `<file>` and deletes the record. The owner
   isn't restored; the file belongs to whoever runs pull.
4. With `--purge`, deletes the remote copy. If that fails, the file is still
   restored; offloader exits non-zero and prints the id that's left on the
   remote.

pull refuses to overwrite an existing `<file>`.

## Flags

Every flag falls back to an environment variable.

| Flag | Env | Used by | Meaning | |---|---|---|---| | `--method dir\|shell` |
`OFFLOADER_METHOD` | push | transport (default `shell`) | | `--dir PATH` |
`OFFLOADER_DIR` | push | target directory for `dir` | | `--put CMD` |
`OFFLOADER_PUT` | push | upload command | | `--get CMD` | `OFFLOADER_GET` |
push | download command (stored in record) | | `--rm CMD` | `OFFLOADER_RM` |
push, pull | remove command (stored in record; at pull, overrides the stored
one) | | `--ext EXT` | `OFFLOADER_EXT` | both | record extension (default
`offload`) | | `--tmp PATH` | `OFFLOADER_TMP` | both | scratch dir root
(default system temp) | | `--no-verify` | `OFFLOADER_NO_VERIFY` | push | skip
the round-trip check | | `--purge` | `OFFLOADER_PURGE` | pull | delete the
remote copy after restoring | | `--no-purge` | — | pull | override
`OFFLOADER_PURGE` for one run | | `--help` | — | | usage |

Passphrase: taken from `$OFFLOADER_PASSPHRASE` if set, otherwise prompted
(twice on push).

On/off env vars accept `1/0`, `true/false`, `yes/no`, `on/off` (any case);
empty means off. Anything else is an error. Purge by default: `export
OFFLOADER_PURGE=1`.

## Security notes

- **Remote:** sees only age ciphertext and a random id. It never sees the
  filename, the key or the passphrase.
- **Record:** encrypted with age's scrypt passphrase mode, which also
  authenticates it. The commands stored inside it run at pull time, so they
  can't be changed without the passphrase.
- **Temporary files:** scratch files are mode `0600` inside a `0700` directory
  and are removed on exit, including error paths.
- **`$OFFLOADER_PASSPHRASE`:** convenient for scripts, but visible to other
  processes running as your user. Prefer the prompt for interactive use.
- **If you lose the passphrase or the record, the file is gone.** That is the
  point of the design, so back up both.

## Limitations

- One regular file at a time. No directories; `tar` them first.
- Without `--purge`, remote blobs stay forever, and offloader has no index of
  them.
- Push needs free temp space about the size of the file (twice that with
  verify).
