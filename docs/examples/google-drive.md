# Example: offload a file to Google Drive

This example moves a large or sensitive document to Google Drive and brings it back when you need it. offloader has no Drive support of its own; the `shell` method drives [rclone](https://rclone.org) instead.

Drive only ever holds ciphertext under a random name. The file is encrypted with a fresh key before it leaves your machine, and that key exists only in the `.offload` record left behind, which is itself encrypted with your passphrase.

## 1. Connect rclone to Drive (once)

[Install rclone](https://rclone.org/install/), then run:

```sh
rclone config
```

- `n` for a new remote, and name it `gdrive`.
- Storage type: `drive`.
- `client_id` / `client_secret`: blank works. rclone's shared client is rate-limited, so for heavy use [make your own](https://rclone.org/drive/#making-your-own-client-id).
- Scope: `drive.file`. rclone can then only see files it created itself, not the rest of your Drive.
- Approve access in the browser. On a machine without one, answer `n` to auto config and follow the `rclone authorize "drive"` instructions.

Check it works:

```sh
rclone lsd gdrive:
```

## 2. Tell offloader how to use it

Add to `~/.bashrc` or `~/.zshrc`:

```sh
export OFFLOADER_PUT='rclone copyto "$SRC" gdrive:offloader/$ID'
export OFFLOADER_GET='rclone copyto gdrive:offloader/$ID "$DST"'
export OFFLOADER_RM='rclone deletefile --drive-use-trash=false gdrive:offloader/$ID'
```

- **Keep the single quotes.** offloader sets `$SRC`, `$DST` and `$ID` itself when it runs each command under `sh -c`; they must not be expanded when you export.
- `copyto` creates the `offloader` folder on first upload.
- `--drive-use-trash=false` deletes for good. Without it, removed blobs sit in Drive's trash for 30 days and count against your storage.
- `OFFLOADER_RM` is optional, but without it `--purge` and `offloader rm` can't delete the Drive copy.

## 3. Upload

```console
$ offloader push taxes-2025.pdf
record passphrase:
confirm passphrase:
offloaded taxes-2025.pdf (2.9 MiB) -> taxes-2025.pdf.offload (id c3594fbf8db609723adff923473c2434)
```

offloader encrypts the file, uploads it, downloads it again to check the copy is intact, writes `taxes-2025.pdf.offload`, and only then deletes `taxes-2025.pdf`. In Drive, the `offloader` folder gets one file named after the id.

The record now holds the three commands above, so pulling later doesn't need the `OFFLOADER_*` variables set.

## 4. Fetch it back

```sh
offloader pull taxes-2025.pdf            # finds taxes-2025.pdf.offload
```

This asks for the passphrase, downloads and decrypts the file, and restores `taxes-2025.pdf` with its original permissions and timestamps. The record is deleted, but the Drive copy stays.

To delete the Drive copy as well:

```sh
offloader pull --purge taxes-2025.pdf
```

If the purge fails (you're offline, say), the file is still restored and the record is kept. Run `offloader rm taxes-2025.pdf.offload` later to finish the removal.

## Pulling on another machine

1. Copy `taxes-2025.pdf.offload` across. It's encrypted, so email or a sync folder is fine.
2. Set up rclone there with a remote called `gdrive` as in step 1.

If you named the remote differently, override the stored command:

```sh
offloader pull --get 'rclone copyto mydrive:offloader/$ID "$DST"' taxes-2025.pdf.offload
```

## Things to know

- **The record is the only key.** Lose `taxes-2025.pdf.offload` or its passphrase and the Drive copy can't be recovered by anyone, you included. Keep a backup of the record somewhere other than the folder it sits in.
- **Scripts and cron jobs:** with no terminal, set `OFFLOADER_PASSPHRASE` instead of typing it.
- **Disk space:** push needs free space the size of the file next to it, and pull needs twice that. `--tmp DIR` moves the scratch copy elsewhere.
- **Folders:** offloader handles one file at a time, so `tar` a folder first.
