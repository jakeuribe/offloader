#!/bin/sh
# End-to-end check: push -> record replaces file, remote holds only ciphertext -> pull restores.
set -eu
cargo build -q --release
BIN="$PWD/target/release/offloader"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir "$T/remote"
OFFLOADER_PASSPHRASE=$(head -c 24 /dev/urandom | base64); export OFFLOADER_PASSPHRASE
export OFFLOADER_PUT="cp \"\$SRC\" '$T/remote/'\$ID"
export OFFLOADER_GET="cp '$T/remote/'\$ID \"\$DST\""
f="$T/my file; rm -rf x.txt"            # hostile-looking name must be harmless
head -c 200000 /dev/urandom > "$f"; echo SECRETMARKER >> "$f"; cp "$f" "$T/orig"

"$BIN" push "$f"
[ ! -e "$f" ] && [ -s "$f.offload" ]
! grep -q SECRETMARKER "$T"/remote/*           # remote is ciphertext
! OFFLOADER_PASSPHRASE=not-the-passphrase "$BIN" pull "$f.offload" 2>/dev/null
"$BIN" pull "$f.offload"
cmp "$f" "$T/orig" && [ ! -e "$f.offload" ]

# tampered remote blob must fail and leave the record intact
"$BIN" push "$f"
for b in "$T"/remote/*; do printf X | dd of="$b" bs=1 seek=500 conv=notrunc 2>/dev/null; done
! "$BIN" pull "$f.offload" 2>/dev/null
[ -e "$f.offload" ] && [ ! -e "$f" ]

# failing put must not delete the original
cp "$T/orig" "$T/g"
! OFFLOADER_PUT=false "$BIN" push "$T/g" 2>/dev/null
cmp "$T/g" "$T/orig" && [ ! -e "$T/g.offload" ]

# dir method + custom extension
mkdir "$T/nas"; cp "$T/orig" "$T/h"
OFFLOADER_METHOD=dir "$BIN" push "$T/h" --dir "$T/nas" --ext vault
[ ! -e "$T/h" ] && [ -s "$T/h.vault" ] && ! grep -q SECRETMARKER "$T"/nas/*
! "$BIN" pull "$T/h.vault" 2>/dev/null          # wrong ext rejected
"$BIN" pull "$T/h.vault" --ext vault
cmp "$T/h" "$T/orig"
! OFFLOADER_METHOD=dir "$BIN" push "$T/h" --dir relative 2>/dev/null   # relative dir rejected
! "$BIN" push "$T/h" --bogus x 2>/dev/null
echo PASS
