#!/bin/sh
# End-to-end check: push -> record replaces file, remote holds only ciphertext -> pull restores.
set -eu
# Clean slate: ignore any OFFLOADER_* settings in the caller's environment.
for v in $(env | sed -n 's/^\(OFFLOADER_[A-Z_]*\)=.*/\1/p'); do unset "$v"; done
cargo build -q --release
BIN="$PWD/target/release/offloader"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir "$T/remote"
# `set -e` ignores `! cmd` and every command of an `a && b` list but the last, so
# assertions go one per statement and negative ones through these.
fails() { if "$@" >/dev/null 2>"$T/err"; then echo "FAIL (should have failed): $*"; exit 1; fi; }
no() { if "$@"; then echo "FAIL: $*"; exit 1; fi; }
OFFLOADER_PASSPHRASE=$(head -c 24 /dev/urandom | base64); export OFFLOADER_PASSPHRASE
export OFFLOADER_PUT="cp \"\$SRC\" '$T/remote/'\$ID"
export OFFLOADER_GET="cp '$T/remote/'\$ID \"\$DST\""
f="$T/my file; rm -rf x.txt"            # hostile-looking name must be harmless
head -c 200000 /dev/urandom > "$f"; echo SECRETMARKER >> "$f"; cp "$f" "$T/orig"

"$BIN" push "$f"
[ ! -e "$f" ]; [ -s "$f.offload" ]
no grep -q SECRETMARKER "$T"/remote/*           # remote is ciphertext
fails env OFFLOADER_PASSPHRASE=not-the-passphrase "$BIN" pull "$f.offload"
"$BIN" pull "$f.offload"
cmp "$f" "$T/orig"; [ ! -e "$f.offload" ]

# tampered remote blob must fail and leave the record intact
"$BIN" push "$f"
for b in "$T"/remote/*; do printf X | dd of="$b" bs=1 seek=500 conv=notrunc 2>/dev/null; done
fails "$BIN" pull "$f.offload"
[ -e "$f.offload" ]; [ ! -e "$f" ]

# failing put must not delete the original
cp "$T/orig" "$T/g"
fails env OFFLOADER_PUT=false "$BIN" push "$T/g"
cmp "$T/g" "$T/orig"; [ ! -e "$T/g.offload" ]

# dir method + custom extension
mkdir "$T/nas"; cp "$T/orig" "$T/h"
OFFLOADER_METHOD=dir "$BIN" push "$T/h" --dir "$T/nas" --ext vault
[ ! -e "$T/h" ]; [ -s "$T/h.vault" ] ; no grep -q SECRETMARKER "$T"/nas/*
fails "$BIN" pull "$T/h.vault"          # wrong ext rejected
"$BIN" pull "$T/h.vault" --ext vault
cmp "$T/h" "$T/orig"
fails env OFFLOADER_METHOD=dir "$BIN" push "$T/h" --dir relative   # relative dir rejected
fails "$BIN" push "$T/h" --bogus x
# --purge: dir method removes the remote blob
cp "$T/orig" "$T/p"
OFFLOADER_METHOD=dir "$BIN" push "$T/p" --dir "$T/nas"
n=$(ls "$T/nas" | wc -l)
"$BIN" pull "$T/p.offload" --purge
cmp "$T/p" "$T/orig"; [ "$(ls "$T/nas" | wc -l)" -eq $((n - 1)) ]

# --purge: shell method uses the --rm stored at push
rm -rf "$T/remote"; mkdir "$T/remote"
"$BIN" push "$T/p" --rm "rm '$T/remote/'\$ID"
"$BIN" pull "$T/p.offload" --purge
cmp "$T/p" "$T/orig"; [ -z "$(ls "$T/remote")" ]

# --purge without any rm cmd fails up front: nothing restored, record kept
"$BIN" push "$T/p"
fails "$BIN" pull "$T/p.offload" --purge
[ -e "$T/p.offload" ]; [ ! -e "$T/p" ]
# ...and --rm at pull time supplies it
"$BIN" pull "$T/p.offload" --purge --rm "rm '$T/remote/'\$ID"
cmp "$T/p" "$T/orig"; [ -z "$(ls "$T/remote")" ]

# failing rm: file still restored, error reported
"$BIN" push "$T/p" --rm false
fails "$BIN" pull "$T/p.offload" --purge
cmp "$T/p" "$T/orig"; [ -e "$T/p.offload" ]; [ -n "$(ls "$T/remote")" ]   # record kept as the handle
"$BIN" rm "$T/p" --rm "rm '$T/remote/'\$ID"                              # ...so rm can retry
[ ! -e "$T/p.offload" ]; [ -z "$(ls "$T/remote")" ]
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
fails env OFFLOADER_PURGE=maybe "$BIN" pull "$T/p.offload"   # junk rejected
"$BIN" pull "$T/p.offload" --purge --no-purge; [ -n "$(ls "$T/remote")" ]   # --no-purge always wins
rm -f "$T/remote"/*; "$BIN" push "$T/p"
OFFLOADER_PURGE=TRUE "$BIN" pull "$T/p.offload"
cmp "$T/p" "$T/orig"; [ -z "$(ls "$T/remote")" ]               # default purge works
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
# --- help text ---
"$BIN" 2>&1 | grep -q 'Usage:' || true; [ -n "$("$BIN" 2>&1 | grep 'Commands:')" ]   # bare = full help
"$BIN" push -V | grep -q '^offloader-push '
"$BIN" --help | grep -q 'Examples:'
"$BIN" --help | grep -q -- '--tmp <PATH>'
h=$("$BIN" push --help)
echo "$h" | grep -q -- '-m, --method <METHOD>'
echo "$h" | grep -q -- '-d, --dir <DIR>'
echo "$h" | grep -q -- '--put <CMD>'
echo "$h" | grep -q 'File to offload'
"$BIN" pull --help | grep -q 'Record to restore'

# --- error messages ---
unset OFFLOADER_RM
fails "$BIN" push "$T/nope.iso";  grep -q 'nope.iso: No such file' "$T/err"
fails "$BIN" pull "$T/nope.iso";  grep -q 'nope.iso.offload: No such file' "$T/err"
mkdir "$T/d"
fails "$BIN" push "$T/d";         grep -q 'is a directory; tar it first' "$T/err"
cp "$T/orig" "$T/w.txt"
fails "$BIN" pull "$T/w.txt";     grep -q 'w.txt: expected a .offload file (--ext' "$T/err"
cp "$T/orig" "$T/r.offload"
fails "$BIN" push "$T/r.offload"; grep -q 'already a .offload record' "$T/err"
[ ! -e "$T/r.offload.offload" ]
cp "$T/orig" "$T/s"
fails "$BIN" push "$T/s" --put false; grep -q 'put command failed' "$T/err"
cmp "$T/s" "$T/orig"

# --- pull by original name; short flags ---
cp "$T/orig" "$T/n"
"$BIN" push "$T/n" -m dir -d "$T/nas"
"$BIN" pull "$T/n"
cmp "$T/n" "$T/orig"; [ ! -e "$T/n.offload" ]
# --- symlinks refused; hard links warned about; size reported ---
ln -s "$T/orig" "$T/link"
fails "$BIN" push "$T/link"; grep -q 'is a symlink' "$T/err"; [ -L "$T/link" ]
cp "$T/orig" "$T/h1"; ln "$T/h1" "$T/h2"
"$BIN" push "$T/h1" 2>"$T/err" | grep -q '(195.3 KiB)'
grep -q '2 hard links' "$T/err"
"$BIN" pull "$T/h1" >/dev/null

# --- failed verify doesn't orphan the upload ---
rm -f "$T/remote"/*; cp "$T/orig" "$T/v"
fails "$BIN" push "$T/v" --get false --rm "rm '$T/remote/'\$ID"
grep -q 'push failed; removed remote copy' "$T/err"; [ -z "$(ls "$T/remote")" ]; cmp "$T/v" "$T/orig"
fails "$BIN" push "$T/v" --get false; grep -q 'was left behind' "$T/err"
rm -f "$T/remote"/*

# --- pull can be pointed at a remote that moved ---
"$BIN" push "$T/v" -m dir -d "$T/nas"; mv "$T/nas" "$T/nas2"
fails "$BIN" pull "$T/v"
fails "$BIN" pull "$T/v" --get true; grep -q 'does not apply' "$T/err"
"$BIN" pull "$T/v" -d "$T/nas2"; cmp "$T/v" "$T/orig"
mkdir "$T/remote2"; "$BIN" push "$T/v"; mv "$T/remote"/* "$T/remote2/"
fails "$BIN" pull "$T/v" -d "$T/nas2"; grep -q 'does not apply' "$T/err"
"$BIN" pull "$T/v" --get "cp '$T/remote2/'\$ID \"\$DST\""; cmp "$T/v" "$T/orig"

# --- rm refuses to destroy the only copy unless forced ---
"$BIN" push "$T/v" --rm "rm '$T/remote/'\$ID"
fails "$BIN" rm "$T/v"; grep -q "is missing or doesn't match" "$T/err"
[ -e "$T/v.offload" ]; [ -n "$(ls "$T/remote")" ]
echo "something else that took the name" > "$T/v"                 # an impostor isn't a restore
fails "$BIN" rm "$T/v"; grep -q "is missing or doesn't match" "$T/err"
[ -e "$T/v.offload" ]; [ -n "$(ls "$T/remote")" ]
rm "$T/v"
"$BIN" rm "$T/v" --force
[ ! -e "$T/v.offload" ]; [ -z "$(ls "$T/remote")" ]

# --- a stale $OFFLOADER_RM can't stand in for the rm a record stored, or block dir ---
cp "$T/orig" "$T/e"
"$BIN" push "$T/e" --rm "rm '$T/remote/'\$ID"
OFFLOADER_RM=true "$BIN" pull "$T/e" --purge
cmp "$T/e" "$T/orig"; [ -z "$(ls "$T/remote")" ]
OFFLOADER_RM=true "$BIN" push "$T/e" -m dir -d "$T/nas2"
"$BIN" pull "$T/e" --purge
cmp "$T/e" "$T/orig"

# --- a dir remote that moved is an error for rm, not "already gone" ---
"$BIN" push "$T/e" -m dir -d "$T/nas2"; mv "$T/nas2" "$T/nas3"
fails "$BIN" rm "$T/e" --force
[ -e "$T/e.offload" ]
mv "$T/nas3" "$T/nas2"; "$BIN" rm "$T/e" --force
[ ! -e "$T/e.offload" ]

# --- no terminal and no passphrase says what to do ---
cp "$T/orig" "$T/q"
( unset OFFLOADER_PASSPHRASE; fails setsid -w "$BIN" push "$T/q" </dev/null )
grep -q 'no passphrase: set \$OFFLOADER_PASSPHRASE' "$T/err"

# scratch dirs live next to the file by default and never outlive a run
[ -z "$(find "$T" -name '.offloader-*')" ]
echo PASS
