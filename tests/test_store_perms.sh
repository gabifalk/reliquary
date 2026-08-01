#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Integration test: on-disk key material must be owner-only -- files 0600 and
# token dirs 0700 -- so it does not depend on the caller's umask and no other
# principal inside the reliquary-group-gated store can read it.
set -e

DAEMON="$1"
TOOL="$2"

if [ -z "$DAEMON" ] || [ -z "$TOOL" ]; then
    echo "Usage: $0 <reliquaryd> <reliquary-tool>" >&2
    exit 1
fi

TMPDIR=$(mktemp -d /tmp/test_store_perms_XXXXXX)
STORE="$TMPDIR/store"
XDG="$TMPDIR/xdg"
SOCK="$XDG/reliquary/socket"
PIN="testpin1234"
DAEMON_PID=""

cleanup() {
    if [ -n "$DAEMON_PID" ]; then
        pkill -TERM -P "$DAEMON_PID" 2>/dev/null || true
        kill "$DAEMON_PID" 2>/dev/null || true
    fi
    wait 2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

PASS=0; FAIL=0; TOTAL=0
run_test() { TOTAL=$((TOTAL + 1)); printf "  %s ... " "$1"; }
ok() { PASS=$((PASS + 1)); echo "ok"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL: $1"; }

# Deliberately permissive parent umask: the daemon must clamp modes itself
# rather than inherit whatever launched it.
umask 022

mkdir -p "$STORE" "$XDG"
XDG_RUNTIME_DIR="$XDG" "$DAEMON" --store "$STORE" 2>/dev/null &
DAEMON_PID=$!
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "daemon socket did not appear" >&2; exit 1; }

export RELIQUARY_SOCKET="$SOCK"

echo "test_store_perms:"

printf 'adminpin\nadminpin\n' | "$TOOL" init >/dev/null 2>&1
printf 'adminpin\n%s\n%s\n' "$PIN" "$PIN" | "$TOOL" create work >/dev/null 2>&1
printf '%s\n' "$PIN" | "$TOOL" genkey work sign ed25519 >/dev/null 2>&1

run_test "token_dir_0700"
mode=$(stat -c '%a' "$STORE/work" 2>/dev/null || echo '?')
if [ "$mode" = "700" ]; then ok; else fail "token dir mode is $mode, want 700"; fi

run_test "key_files_0600"
bad=""
found=0
for f in "$STORE"/work/*; do
    [ -f "$f" ] || continue
    found=$((found + 1))
    m=$(stat -c '%a' "$f")
    [ "$m" = "600" ] || bad="$bad $(basename "$f"):$m"
done
if [ "$found" -eq 0 ]; then
    fail "no key files found under $STORE/work"
elif [ -z "$bad" ]; then
    ok
else
    fail "non-0600 files:$bad"
fi

echo "$PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ]
