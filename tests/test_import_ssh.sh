#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Integration test: import an OpenSSH key via reliquary-tool import-ssh,
# then confirm the imported key is visible/usable through the PKCS#11 module.
set -e

DAEMON="$1"
TOOL="$2"
LIBP11="$3"

if [ -z "$DAEMON" ] || [ -z "$TOOL" ] || [ -z "$LIBP11" ]; then
    echo "Usage: $0 <reliquaryd> <reliquary-tool> <reliquary-pkcs11.so>" >&2
    exit 1
fi

for cmd in ssh-keygen python3; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo "SKIP: $cmd not found" >&2
        exit 77
    }
done

# Open a fresh connection to the daemon and LOGIN to a token. This forces the
# daemon to re-read the slot key file from disk and decrypt it with the
# unwrapped master key (session_login -> keywrap_open -> keyfile_open), which
# is exactly what the PKCS#11 module's C_Login does for ssh. Prints "OK" on
# success. A key sealed under the wrong bytes at import time decrypts the
# master-key envelope fine but fails here -- the regression guard for the
# assuan_inquire buffer-reuse bug in cmd_import_slot.
fresh_login() {
    python3 - "$SOCK" "$@" <<'PYEOF'
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
                print(line.decode(errors='replace'), file=sys.stderr)
                return False
        time.sleep(0.02)

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)
if not read_reply(s):            # server greeting
    sys.exit(1)
for cmd in (f"OPEN_SESSION {label}", f"LOGIN {pin}"):
    s.sendall((cmd + "\n").encode())
    if not read_reply(s):
        s.close(); sys.exit(1)
s.sendall(b"CLOSE_SESSION\n"); read_reply(s)
s.close()
print("OK")
sys.exit(0)
PYEOF
}

TMPDIR=$(mktemp -d /tmp/test_import_ssh_XXXXXX)
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

echo "test_import_ssh:"

# Generate unencrypted keys to import. ECDSA is used for the PKCS#11
# verification because it works on any OpenSSH; Ed25519 over PKCS#11 needs
# OpenSSH >= 10.1, so here ed25519 is checked only for import success.
ssh-keygen -q -t ecdsa -b 256 -N '' -C '' -f "$TMPDIR/id_ecdsa"
ssh-keygen -q -t ed25519 -N '' -C '' -f "$TMPDIR/id_ed25519"

# Store init + two tokens (feed PINs on stdin: admin, token, confirm).
run_test "init_store"
if printf 'adminpin\nadminpin\n' | "$TOOL" init >/dev/null 2>&1; then ok; else fail "init"; fi

run_test "create_token_ec"
if printf 'adminpin\n%s\n%s\n' "$PIN" "$PIN" | "$TOOL" create work \
        >/dev/null 2>&1; then ok; else fail "create"; fi

# import-ssh an ECDSA key into the existing token's auth slot (token PIN on stdin).
run_test "import_ssh_ecdsa"
if printf '%s\n' "$PIN" | "$TOOL" import-ssh work auth \
        "$TMPDIR/id_ecdsa" >"$TMPDIR/import.out" 2>&1; then
    if grep -q "Imported nistp256 key into auth slot" "$TMPDIR/import.out"; then
        ok
    else
        cat "$TMPDIR/import.out" >&2
        fail "unexpected output"
    fi
else
    cat "$TMPDIR/import.out" >&2
    fail "import-ssh returned error"
fi

# The imported ECDSA key must appear via the PKCS#11 module.
run_test "pkcs11_sees_ecdsa_key"
KEYS=$(ssh-keygen -D "$LIBP11" 2>"$TMPDIR/keygen.err") || true
if echo "$KEYS" | grep -q "^ecdsa-sha2-nistp256"; then
    ok
else
    cat "$TMPDIR/keygen.err" >&2
    fail "ecdsa key not visible via PKCS#11"
fi

# A fresh LOGIN must decrypt the imported key file from disk with the token
# PIN -- the path C_Login takes for ssh. Listing the public key above only
# reads metadata; this is what actually exercises the sealed private key.
run_test "login_decrypts_imported_ecdsa"
if [ "$(fresh_login work "$PIN" 2>"$TMPDIR/login.err")" = "OK" ]; then
    ok
else
    cat "$TMPDIR/login.err" >&2
    fail "fresh login could not decrypt the imported key (import sealed it wrong)"
fi

# ed25519 import must also succeed (usable via the gpg-agent/OpenPGP path;
# not exposed over PKCS#11 by design).
run_test "create_token_ed"
if printf 'adminpin\n%s\n%s\n' "$PIN" "$PIN" | "$TOOL" create worked \
        >/dev/null 2>&1; then ok; else fail "create"; fi

run_test "import_ssh_ed25519_succeeds"
if printf '%s\n' "$PIN" | "$TOOL" import-ssh worked auth \
        "$TMPDIR/id_ed25519" >"$TMPDIR/import_ed.out" 2>&1; then
    if grep -q "Imported ed25519 key into auth slot" "$TMPDIR/import_ed.out"; then
        ok
    else
        cat "$TMPDIR/import_ed.out" >&2
        fail "unexpected output"
    fi
else
    cat "$TMPDIR/import_ed.out" >&2
    fail "ed25519 import-ssh returned error"
fi

# ed25519 is hidden from PKCS#11 by design, but the daemon must still decrypt
# it on a fresh login (the OpenPGP/gpg-agent path uses the same key file).
run_test "login_decrypts_imported_ed25519"
if [ "$(fresh_login worked "$PIN" 2>"$TMPDIR/login_ed.err")" = "OK" ]; then
    ok
else
    cat "$TMPDIR/login_ed.err" >&2
    fail "fresh login could not decrypt the imported ed25519 key"
fi

echo "$PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
