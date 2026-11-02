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
# --purge: dir method removes the remote blob
cp "$T/orig" "$T/p"
OFFLOADER_METHOD=dir "$BIN" push "$T/p" --dir "$T/nas"
n=$(ls "$T/nas" | wc -l)
"$BIN" pull "$T/p.offload" --purge
cmp "$T/p" "$T/orig" && [ "$(ls "$T/nas" | wc -l)" -eq $((n - 1)) ]
! OFFLOADER_METHOD=dir "$BIN" push "$T/p" --dir "$T/nas" --rm true 2>/dev/null   # --rm invalid for dir

# --purge: shell method uses the --rm stored at push
rm -rf "$T/remote"; mkdir "$T/remote"
"$BIN" push "$T/p" --rm "rm '$T/remote/'\$ID"
"$BIN" pull "$T/p.offload" --purge
cmp "$T/p" "$T/orig" && [ -z "$(ls "$T/remote")" ]

# --purge without any rm cmd fails up front: nothing restored, record kept
"$BIN" push "$T/p"
! "$BIN" pull "$T/p.offload" --purge 2>/dev/null
[ -e "$T/p.offload" ] && [ ! -e "$T/p" ]
# ...and --rm at pull time supplies it
"$BIN" pull "$T/p.offload" --purge --rm "rm '$T/remote/'\$ID"
cmp "$T/p" "$T/orig" && [ -z "$(ls "$T/remote")" ]

# failing rm: file still restored, error reported
"$BIN" push "$T/p" --rm false
! "$BIN" pull "$T/p.offload" --purge 2>/dev/null
cmp "$T/p" "$T/orig" && [ ! -e "$T/p.offload" ] && [ -n "$(ls "$T/remote")" ]
# purge as a default via env, --no-purge overrides, bad/zero values handled
rm -rf "$T/remote"; mkdir "$T/remote"
export OFFLOADER_RM="rm '$T/remote/'\$ID"
"$BIN" push "$T/p"; OFFLOADER_PURGE=0 "$BIN" pull "$T/p.offload"
[ -n "$(ls "$T/remote")" ]                                       # 0 means off
rm -f "$T/remote"/*
"$BIN" push "$T/p"; OFFLOADER_PURGE=yes "$BIN" pull "$T/p.offload" --no-purge
[ -n "$(ls "$T/remote")" ]                                       # --no-purge wins
rm -f "$T/remote"/*
"$BIN" push "$T/p"
! OFFLOADER_PURGE=maybe "$BIN" pull "$T/p.offload" 2>/dev/null   # junk rejected
"$BIN" pull "$T/p.offload" --purge --no-purge; [ -n "$(ls "$T/remote")" ]   # --no-purge always wins
rm -f "$T/remote"/*; "$BIN" push "$T/p"
OFFLOADER_PURGE=TRUE "$BIN" pull "$T/p.offload"
cmp "$T/p" "$T/orig" && [ -z "$(ls "$T/remote")" ]               # default purge works
# metadata: mode + mtime/atime survive the round trip (incl. read-only and pre-1970)
unset OFFLOADER_PURGE
for spec in "755 2001-02-03T04:05:06.123456789" "444 1960-01-01T00:00:00.5" "4750 2020-06-01T12:00:00"; do
  set -- $spec
  m="$T/meta"; cp "$T/orig" "$m"; chmod "$1" "$m"; touch -d "$2" "$m"
  before=$(stat -c '%a %y %x' "$m")
  "$BIN" push "$m" >/dev/null; "$BIN" pull "$m.offload" >/dev/null
  [ "$(stat -c '%a %y %x' "$m")" = "$before" ] || { echo "meta mismatch: $before vs $(stat -c '%a %y %x' "$m")"; exit 1; }
  cmp "$m" "$T/orig"; chmod u+w "$m"; rm -f "$m"
done
echo PASS
