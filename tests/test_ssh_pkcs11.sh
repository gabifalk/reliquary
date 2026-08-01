#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Integration test: use ssh-keygen with reliquary PKCS#11 module
# to extract public keys, sign data, and verify signatures.
set -e

DAEMON="$1"
LIBP11="$2"

if [ -z "$DAEMON" ] || [ -z "$LIBP11" ]; then
    echo "Usage: $0 <reliquaryd> <reliquary-pkcs11.so>" >&2
    exit 1
fi

for cmd in ssh-keygen python3; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo "SKIP: $cmd not found" >&2
        exit 77
    }
done

TMPDIR=$(mktemp -d /tmp/test_ssh_p11_XXXXXX)
STORE="$TMPDIR/store"
XDG="$TMPDIR/xdg"
SOCK="$XDG/reliquary/socket"
PIN="testpin1234"
DAEMON_PID=""

cleanup() {
    [ -n "$AGENT_PID" ] && kill "$AGENT_PID" 2>/dev/null || true
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

echo "test_ssh_pkcs11:"

run_test "create_rsa_token"
if create_token "sshkey" "rsa2048" "$PIN"; then ok; else fail "create"; fi

run_test "create_ec_token"
if create_token "sshec" "nistp256" "$PIN"; then ok; else fail "create"; fi

# ssh-keygen -D extracts public keys directly from the PKCS#11 module
run_test "ssh_keygen_extract_pubkeys"
KEYS=$(ssh-keygen -D "$LIBP11" 2>"$TMPDIR/keygen.err") || true
NKEYS=$(echo "$KEYS" | grep -c "^ssh-\|^ecdsa-" || true)
if [ "$NKEYS" -ge 1 ]; then
    ok
else
    echo "" >&2
    echo "--- ssh-keygen -D stderr ---" >&2
    cat "$TMPDIR/keygen.err" >&2
    fail "expected >=1 key, got $NKEYS"
fi

run_test "has_rsa_key"
if echo "$KEYS" | grep -q "^ssh-rsa"; then ok; else fail "no ssh-rsa"; fi

run_test "has_ecdsa_key"
if echo "$KEYS" | grep -q "^ecdsa-sha2"; then ok; else fail "no ecdsa"; fi

# Verify RSA key is valid by checking key length
run_test "rsa_key_valid"
RSA_PUB=$(echo "$KEYS" | grep "^ssh-rsa" | head -1)
if [ -n "$RSA_PUB" ]; then
    echo "$RSA_PUB" > "$TMPDIR/rsa.pub"
    BITS=$(ssh-keygen -l -f "$TMPDIR/rsa.pub" 2>/dev/null | awk '{print $1}')
    if [ "$BITS" = "2048" ]; then
        ok
    else
        fail "expected 2048 bits, got $BITS"
    fi
else
    fail "no RSA key"
fi

# Verify ECDSA key is valid by checking key length
run_test "ecdsa_key_valid"
EC_PUB=$(echo "$KEYS" | grep "^ecdsa-sha2" | head -1)
if [ -n "$EC_PUB" ]; then
    echo "$EC_PUB" > "$TMPDIR/ec.pub"
    BITS=$(ssh-keygen -l -f "$TMPDIR/ec.pub" 2>/dev/null | awk '{print $1}')
    if [ "$BITS" = "256" ]; then
        ok
    else
        fail "expected 256 bits, got $BITS"
    fi
else
    fail "no ECDSA key"
fi

# --- SSH agent signing tests ---
# Start ssh-agent with our provider whitelisted

ASKPASS="$TMPDIR/askpass.sh"
printf '#!/bin/sh\necho "%s"\n' "$PIN" > "$ASKPASS"
chmod +x "$ASKPASS"

SSH_AUTH_SOCK="$TMPDIR/agent.sock"
export SSH_AUTH_SOCK
export SSH_ASKPASS="$ASKPASS"
export SSH_ASKPASS_REQUIRE="force"
export DISPLAY="dummy:0"

ssh-agent -d -a "$SSH_AUTH_SOCK" -P "$LIBP11" >"$TMPDIR/agent.log" 2>&1 &
AGENT_PID=$!
for i in $(seq 1 20); do [ -S "$SSH_AUTH_SOCK" ] && break; sleep 0.1; done

if [ -S "$SSH_AUTH_SOCK" ]; then

    # Load PKCS#11 provider into agent
    run_test "ssh_add_provider"
    ADD_OUT=$(setsid -w ssh-add -v -s "$LIBP11" 2>&1) || true
    if echo "$ADD_OUT" | grep -q "Card added"; then
        ok
    else
        echo "$ADD_OUT" >&2
        fail "ssh-add -s"
    fi

    # List keys from agent
    run_test "agent_has_keys"
    AGENT_KEYS=$(ssh-add -L 2>/dev/null || true)
    NKEYS=$(echo "$AGENT_KEYS" | grep -c "^ssh-\|^ecdsa-" || true)
    if [ "$NKEYS" -ge 1 ]; then
        ok
    else
        fail "expected >=1 key, got $NKEYS"
    fi

    # Sign and verify with RSA via agent
    run_test "rsa_sign_verify"
    RSA_PUB=$(echo "$AGENT_KEYS" | grep "^ssh-rsa" | head -1)
    if [ -n "$RSA_PUB" ]; then
        echo "$RSA_PUB" > "$TMPDIR/rsa_agent.pub"
        echo "testuser $RSA_PUB" > "$TMPDIR/signers"
        echo "hello from reliquary" > "$TMPDIR/message"
        if ssh-keygen -Y sign -f "$TMPDIR/rsa_agent.pub" -n test \
                < "$TMPDIR/message" > "$TMPDIR/sig" 2>"$TMPDIR/sign.err"; then
            if ssh-keygen -Y verify -f "$TMPDIR/signers" -I testuser -n test \
                    -s "$TMPDIR/sig" < "$TMPDIR/message" 2>/dev/null; then
                ok
            else
                fail "RSA verify failed"
            fi
        else
            cat "$TMPDIR/sign.err" >&2
            fail "RSA sign failed"
        fi
    else
        fail "no RSA key in agent"
    fi

    # Sign and verify with ECDSA via agent
    run_test "ecdsa_sign_verify"
    EC_PUB=$(echo "$AGENT_KEYS" | grep "^ecdsa-sha2" | head -1)
    if [ -n "$EC_PUB" ]; then
        echo "$EC_PUB" > "$TMPDIR/ec_agent.pub"
        echo "ecuser $EC_PUB" > "$TMPDIR/ec_signers"
        echo "hello EC" > "$TMPDIR/ec_message"
        if ssh-keygen -Y sign -f "$TMPDIR/ec_agent.pub" -n test \
                < "$TMPDIR/ec_message" > "$TMPDIR/ec_sig" 2>"$TMPDIR/ec_sign.err"; then
            if ssh-keygen -Y verify -f "$TMPDIR/ec_signers" -I ecuser -n test \
                    -s "$TMPDIR/ec_sig" < "$TMPDIR/ec_message" 2>/dev/null; then
                ok
            else
                fail "EC verify failed"
            fi
        else
            cat "$TMPDIR/ec_sign.err" >&2
            fail "EC sign failed"
        fi
    else
        fail "no ECDSA key in agent"
    fi

    # Remove provider
    run_test "ssh_remove_provider"
    if ssh-add -e "$LIBP11" 2>/dev/null; then ok; else fail "ssh-add -e"; fi

    kill "$AGENT_PID" 2>/dev/null || true
    wait "$AGENT_PID" 2>/dev/null || true

else
    echo "SKIP: ssh-agent failed to start" >&2
fi

echo "$PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
