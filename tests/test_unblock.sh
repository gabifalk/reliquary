#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Integration test: lock a token, then recover it with reliquary-tool unblock.
set -e

DAEMON="$1"
TOOL="$2"

if [ -z "$DAEMON" ] || [ -z "$TOOL" ]; then
    echo "Usage: $0 <reliquaryd> <reliquary-tool>" >&2
    exit 1
fi

command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 not found" >&2; exit 77; }

# try_login <label> <pin>: exit 0 if LOGIN succeeds, 1 otherwise.
try_login() {
    python3 - "$SOCK" "$1" "$2" <<'PYEOF'
import socket, sys, time
sock_path, label, pin = sys.argv[1], sys.argv[2], sys.argv[3]

def read_reply(s):
    buf = b''
    while True:
        chunk = s.recv(4096)
        if not chunk:
            return False
        buf += chunk
        for line in buf.split(b'\n'):
            if line.startswith(b'OK'):
                return True
            if line.startswith(b'ERR'):
                return False
        time.sleep(0.02)

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)
if not read_reply(s):
    sys.exit(1)
s.sendall((f"OPEN_SESSION {label}\n").encode())
if not read_reply(s):
    s.close(); sys.exit(1)
s.sendall((f"LOGIN {pin}\n").encode())
ok = read_reply(s)
s.sendall(b"CLOSE_SESSION\n"); read_reply(s)
s.close()
sys.exit(0 if ok else 1)
PYEOF
}

TMPDIR=$(mktemp -d /tmp/test_unblock_XXXXXX)
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

mkdir -p "$STORE" "$XDG"
XDG_RUNTIME_DIR="$XDG" "$DAEMON" --store "$STORE" 2>/dev/null &
DAEMON_PID=$!
for i in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "daemon socket did not appear" >&2; exit 1; }

export RELIQUARY_SOCKET="$SOCK"

echo "test_unblock:"

run_test "init_store"
if printf 'adminpin\nadminpin\n' | "$TOOL" init >/dev/null 2>&1; then ok; else fail "init"; fi

run_test "create_token"
if printf 'adminpin\n%s\n%s\n' "$PIN" "$PIN" | "$TOOL" create work \
        >/dev/null 2>&1; then ok; else fail "create"; fi

# Lock the token: 3 wrong LOGINs exhaust the retry counter.
run_test "lock_token"
try_login work wrongpin || true
try_login work wrongpin || true
try_login work wrongpin || true
if try_login work "$PIN"; then fail "token not locked"; else ok; fi

# Wrong admin PIN must not unblock.
run_test "unblock_wrong_admin_rejected"
if printf 'wrongadmin\n' | "$TOOL" unblock work >/dev/null 2>&1; then
    fail "wrong admin PIN accepted"
elif try_login work "$PIN"; then
    fail "token unblocked despite wrong admin PIN"
else
    ok
fi

# Correct admin PIN unblocks; the original token PIN logs in again.
run_test "unblock_restores_login"
if printf 'adminpin\n' | "$TOOL" unblock work >/dev/null 2>&1; then
    if try_login work "$PIN"; then ok; else fail "login still fails after unblock"; fi
else
    fail "unblock returned error"
fi

echo "$PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ]
