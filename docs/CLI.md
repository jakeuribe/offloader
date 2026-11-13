# Command-Line Help for `offloader`

This document contains the help content for the `offloader` command-line program.

**Command Overview:**

* [`offloader`↴](#offloader)
* [`offloader push`↴](#offloader-push)
* [`offloader pull`↴](#offloader-pull)
* [`offloader rm`↴](#offloader-rm)

## `offloader`

Offload a file elsewhere and leave an encrypted retrieval record in its place

**Usage:** `offloader [OPTIONS] <COMMAND>`

```text
Examples:
  offloader push bigfile.iso            # encrypt, upload, verify, delete local
  offloader pull bigfile.iso.offload    # fetch, decrypt, restore

Shell method setup (commands run under `sh -c` with $SRC, $DST, $ID in the env):
  export OFFLOADER_PUT='scp -q "$SRC" me@host:offload/$ID'
  export OFFLOADER_GET='scp -q me@host:offload/$ID "$DST"'
  export OFFLOADER_RM='ssh me@host rm offload/$ID'

Passphrase: $OFFLOADER_PASSPHRASE or prompt.
```

###### **Subcommands:**

* `push` — Encrypt + upload FILE, verify, then replace it with FILE.EXT
* `pull` — Fetch + decrypt the file a record points to, restoring it in place
* `rm` — Delete the remote copy a record points to, then the record (after a failed --purge)

###### **Options:**

* `--ext <EXT>` — Record file extension

  Default value: `offload`
* `--tmp <PATH>` — Root for private scratch dirs [default: next to the file]



## `offloader push`

Encrypt + upload FILE, verify, then replace it with FILE.EXT

**Usage:** `offloader push [OPTIONS] <FILE>`

###### **Arguments:**

* `<FILE>` — File to offload; replaced by FILE.EXT once the remote copy is verified

###### **Options:**

* `-m`, `--method <METHOD>` — How the blob leaves the machine

  Default value: `shell`

  Possible values:
  - `dir`:
    Copy into a local directory (NAS mount, USB, …)
  - `shell`:
    Run user-supplied put/get/rm commands

* `-d`, `--dir <DIR>` — Target directory (absolute) for the dir method
* `--put <CMD>` — Upload command (shell method)
* `--get <CMD>` — Download command (shell method; stored in the record)
* `--rm <CMD>` — Remove command for later purges (shell method; stored in the record)
* `--no-verify` — Skip downloading the copy back to verify it before deleting the original



## `offloader pull`

Fetch + decrypt the file a record points to, restoring it in place

**Usage:** `offloader pull [OPTIONS] <RECORD>`

###### **Arguments:**

* `<RECORD>` — Record to restore from, or the original file name if FILE.EXT exists

###### **Options:**

* `--purge` — Delete the remote copy after a successful restore
* `--no-purge` — Keep the remote copy; always wins over --purge / $OFFLOADER_PURGE
* `--rm <CMD>` — Remove command, overriding the one stored in the record (shell method)
* `--get <CMD>` — Download command, overriding the one stored in the record (shell method)
* `-d`, `--dir <DIR>` — Directory holding the remote copy, if it moved since push (dir method)



## `offloader rm`

Delete the remote copy a record points to, then the record (after a failed --purge)

**Usage:** `offloader rm [OPTIONS] <RECORD>`

###### **Arguments:**

* `<RECORD>` — Record whose remote copy should go, or the original file name

###### **Options:**

* `--rm <CMD>` — Remove command, overriding the one stored in the record (shell method)
* `--force` — Proceed even if the file has not been restored (destroys the only copy)



