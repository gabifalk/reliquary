#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Integration test: exercise reliquary PKCS#11 module with pkcs11-tool
set -e

DAEMON="$1"
LIBP11="$2"

if [ -z "$DAEMON" ] || [ -z "$LIBP11" ]; then
    echo "Usage: $0 <reliquaryd> <reliquary-pkcs11.so>" >&2
    exit 1
fi

for cmd in pkcs11-tool python3; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo "SKIP: $cmd not found" >&2
        exit 77
    }
done

TMPDIR=$(mktemp -d /tmp/test_p11tool_XXXXXX)
STORE="$TMPDIR/store"
XDG="$TMPDIR/xdg"
SOCK="$XDG/reliquary/socket"
PIN="testpin1234"
DAEMON_PID=""
P11="--module $LIBP11"

cleanup() {
    if [ -n "$DAEMON_PID" ]; then
        pkill -TERM -P "$DAEMON_PID" 2>/dev/null || true
        kill "$DAEMON_PID" 2>/dev/null || true
    fi
    wait 2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

PASS=0
FAIL=0
TOTAL=0

run_test() { TOTAL=$((TOTAL + 1)); printf "  %s ... " "$1"; }
ok() { PASS=$((PASS + 1)); echo "ok"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL: $1"; }

# --- start daemon ---

mkdir -p "$STORE" "$XDG"
XDG_RUNTIME_DIR="$XDG" "$DAEMON" --store "$STORE" 2>/dev/null &
DAEMON_PID=$!

for i in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "daemon socket did not appear" >&2; exit 1; }

export RELIQUARY_SOCKET="$SOCK"

# --- create tokens ---

create_token() {
    python3 - "$SOCK" "$@" <<'PYEOF'
import socket, sys, time
sock_path, label, algo, pin = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)

def read_ok(s):
    buf = b''
    while True:
        buf += s.recv(4096)
        for line in buf.split(b'\n'):
            if line.startswith(b'OK'):
                return True
            if line.startswith(b'ERR'):
                print(line.decode(), file=sys.stderr)
                return False
        time.sleep(0.05)

# Read server greeting
if not read_ok(s):
    sys.exit(1)

# INIT_STORE (ignore error if already done)
s.sendall(b"INIT_STORE adminpin\n")
read_ok(s)

# CREATE_TOKEN label pin admin-pin
s.sendall(f"CREATE_TOKEN {label} {pin} adminpin\n".encode())
if not read_ok(s):
    s.close(); sys.exit(1)

# OPEN_SESSION label
s.sendall(f"OPEN_SESSION {label}\n".encode())
if not read_ok(s):
    s.close(); sys.exit(1)

# LOGIN pin
s.sendall(f"LOGIN {pin}\n".encode())
if not read_ok(s):
    s.close(); sys.exit(1)

# GENKEY 0 algo bits
s.sendall(f"GENKEY 0 {algo}\n".encode())
if not read_ok(s):
    s.close(); sys.exit(1)

# CLOSE_SESSION
s.sendall(b"CLOSE_SESSION\n")
read_ok(s)

s.close()
sys.exit(0)
PYEOF
}

# --- tests ---

echo "test_pkcs11_tool:"

run_test "create_rsa_token"
if create_token "rsakey" "rsa2048" "$PIN"; then ok; else fail "create rsa"; fi

run_test "create_ec_token"
if create_token "eckey" "nistp256" "$PIN"; then ok; else fail "create ec"; fi

# show-info
run_test "show_info"
if pkcs11-tool $P11 --show-info >"$TMPDIR/info.out" 2>&1; then
    if grep -qi "reliquary\|Cryptoki" "$TMPDIR/info.out"; then
        ok
    else
        fail "no library info"
    fi
else
    cat "$TMPDIR/info.out" >&2
    fail "pkcs11-tool --show-info failed"
fi

# list-slots
run_test "list_slots"
if pkcs11-tool $P11 --list-slots >"$TMPDIR/slots.out" 2>&1; then
    if grep -q "rsakey\|eckey" "$TMPDIR/slots.out"; then
        ok
    else
        cat "$TMPDIR/slots.out" >&2
        fail "tokens not found in slot list"
    fi
else
    fail "pkcs11-tool --list-slots failed"
fi

# list-token-slots
run_test "list_token_slots"
if pkcs11-tool $P11 --list-token-slots >"$TMPDIR/tslots.out" 2>&1; then
    ok
else
    fail "pkcs11-tool --list-token-slots failed"
fi

# list-mechanisms
run_test "list_mechanisms"
if pkcs11-tool $P11 --list-mechanisms >"$TMPDIR/mechs.out" 2>&1; then
    if grep -q "RSA-PKCS\|ECDSA" "$TMPDIR/mechs.out"; then
        ok
    else
        cat "$TMPDIR/mechs.out" >&2
        fail "expected mechanisms not found"
    fi
else
    fail "pkcs11-tool --list-mechanisms failed"
fi

# list-objects (without login -- should see key objects)
run_test "list_objects"
if pkcs11-tool $P11 --list-objects >"$TMPDIR/objs.out" 2>&1; then
    if grep -qi "key" "$TMPDIR/objs.out"; then
        ok
    else
        cat "$TMPDIR/objs.out" >&2
        fail "no key objects"
    fi
else
    fail "pkcs11-tool --list-objects failed"
fi

# list-objects with login -- should see private keys too
run_test "list_objects_with_login"
if pkcs11-tool $P11 --list-objects --login --pin "$PIN" >"$TMPDIR/objs_login.out" 2>&1; then
    if grep -qi "private\|Private" "$TMPDIR/objs_login.out"; then
        ok
    else
        cat "$TMPDIR/objs_login.out" >&2
        fail "no private key objects after login"
    fi
else
    cat "$TMPDIR/objs_login.out" >&2
    fail "pkcs11-tool --list-objects --login failed"
fi

# RSA sign
run_test "rsa_sign"
dd if=/dev/urandom of="$TMPDIR/data.bin" bs=32 count=1 2>/dev/null
if pkcs11-tool $P11 --sign --token-label rsakey --login --pin "$PIN" \
        -m RSA-PKCS --input-file "$TMPDIR/data.bin" \
        --output-file "$TMPDIR/sig.bin" 2>"$TMPDIR/sign.err"; then
    if [ -s "$TMPDIR/sig.bin" ]; then
        ok
    else
        fail "empty signature"
    fi
else
    cat "$TMPDIR/sign.err" >&2
    fail "pkcs11-tool --sign (RSA) failed"
fi

# ECDSA sign
run_test "ecdsa_sign"
if pkcs11-tool $P11 --sign --token-label eckey --login --pin "$PIN" \
        -m ECDSA --input-file "$TMPDIR/data.bin" \
        --output-file "$TMPDIR/ec_sig.bin" 2>"$TMPDIR/ec_sign.err"; then
    if [ -s "$TMPDIR/ec_sig.bin" ]; then
        ok
    else
        fail "empty signature"
    fi
else
    cat "$TMPDIR/ec_sign.err" >&2
    fail "pkcs11-tool --sign (ECDSA) failed"
fi

# test login with wrong PIN
run_test "wrong_pin_rejected"
if pkcs11-tool $P11 --list-objects --login --pin "wrongpin" 2>"$TMPDIR/badpin.err"; then
    fail "should have been rejected"
else
    ok
fi

echo "$PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
