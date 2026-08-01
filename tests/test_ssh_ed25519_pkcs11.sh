#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Integration test: Ed25519 over PKCS#11 through stock ssh-keygen / ssh-agent.
# Requires OpenSSH >= 10.1 (Ed25519 PKCS#11 support); skips otherwise.
set -e

DAEMON="$1"
LIBP11="$2"

if [ -z "$DAEMON" ] || [ -z "$LIBP11" ]; then
    echo "Usage: $0 <reliquaryd> <reliquary-pkcs11.so>" >&2
    exit 1
fi

for cmd in ssh-keygen ssh-agent ssh-add python3; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "SKIP: $cmd not found" >&2; exit 77; }
done

# Require OpenSSH >= 10.1 for Ed25519 PKCS#11 support.
VER=$(ssh -V 2>&1 | sed -n 's/^OpenSSH_\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
MAJ=${VER%%.*}
MIN=${VER#*.}
if [ -z "$VER" ] || [ "$MAJ" -lt 10 ] || { [ "$MAJ" -eq 10 ] && [ "$MIN" -lt 1 ]; }; then
    echo "SKIP: OpenSSH >= 10.1 required for Ed25519 PKCS#11 (have '${VER:-unknown}')" >&2
    exit 77
fi

TMPDIR=$(mktemp -d /tmp/test_ssh_ed_XXXXXX)
STORE="$TMPDIR/store"
XDG="$TMPDIR/xdg"
SOCK="$XDG/reliquary/socket"
PIN="testpin1234"
DAEMON_PID=""
AGENT_PID=""

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

# Create an Ed25519 token (GENKEY into slot 0).
python3 - "$SOCK" "edssh" "ed25519" "$PIN" <<'PYEOF'
import socket, sys, time
sock_path, label, algo, pin = sys.argv[1:5]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(sock_path)
def read_ok(s):
    buf = b''
    while True:
        buf += s.recv(4096)
        for line in buf.split(b'\n'):
            if line.startswith(b'OK'): return True
            if line.startswith(b'ERR'):
                print(line.decode(), file=sys.stderr); return False
        time.sleep(0.05)
read_ok(s)
s.sendall(b"INIT_STORE adminpin\n"); read_ok(s)
s.sendall(f"CREATE_TOKEN {label} {pin} adminpin\n".encode()); read_ok(s)
s.sendall(f"OPEN_SESSION {label}\n".encode()); read_ok(s)
s.sendall(f"LOGIN {pin}\n".encode()); read_ok(s)
s.sendall(f"GENKEY 0 {algo}\n".encode()); read_ok(s)
s.sendall(b"CLOSE_SESSION\n"); read_ok(s); s.close()
PYEOF

echo "test_ssh_ed25519_pkcs11:"

# ssh-keygen -D lists the Ed25519 public key.
run_test "ssh_keygen_lists_ed25519"
KEYS=$(ssh-keygen -D "$LIBP11" 2>"$TMPDIR/keygen.err") || true
if echo "$KEYS" | grep -q "^ssh-ed25519"; then
    ok
else
    cat "$TMPDIR/keygen.err" >&2
    fail "no ssh-ed25519 from ssh-keygen -D"
fi

# Load the provider into ssh-agent and sign/verify.
ASKPASS="$TMPDIR/askpass.sh"
printf '#!/bin/sh\necho "%s"\n' "$PIN" > "$ASKPASS"; chmod +x "$ASKPASS"
SSH_AUTH_SOCK="$TMPDIR/agent.sock"
export SSH_AUTH_SOCK SSH_ASKPASS="$ASKPASS" SSH_ASKPASS_REQUIRE="force" DISPLAY="dummy:0"

ssh-agent -d -a "$SSH_AUTH_SOCK" -P "$LIBP11" >"$TMPDIR/agent.log" 2>&1 &
AGENT_PID=$!
for i in $(seq 1 20); do [ -S "$SSH_AUTH_SOCK" ] && break; sleep 0.1; done

if [ -S "$SSH_AUTH_SOCK" ]; then
    run_test "ssh_add_provider"
    ADD_OUT=$(setsid -w ssh-add -v -s "$LIBP11" 2>&1) || true
    echo "$ADD_OUT" | grep -q "Card added" && ok || { echo "$ADD_OUT" >&2; fail "ssh-add -s"; }

    run_test "ed25519_sign_verify"
    AGENT_KEYS=$(ssh-add -L 2>/dev/null || true)
    ED_PUB=$(echo "$AGENT_KEYS" | grep "^ssh-ed25519" | head -1)
    if [ -n "$ED_PUB" ]; then
        echo "$ED_PUB" > "$TMPDIR/ed.pub"
        echo "eduser $ED_PUB" > "$TMPDIR/ed_signers"
        echo "hello ed25519" > "$TMPDIR/ed_msg"
        if ssh-keygen -Y sign -f "$TMPDIR/ed.pub" -n test \
                < "$TMPDIR/ed_msg" > "$TMPDIR/ed_sig" 2>"$TMPDIR/ed_sign.err" \
           && ssh-keygen -Y verify -f "$TMPDIR/ed_signers" -I eduser -n test \
                -s "$TMPDIR/ed_sig" < "$TMPDIR/ed_msg" 2>/dev/null; then
            ok
        else
            cat "$TMPDIR/ed_sign.err" >&2; fail "ed25519 sign/verify"
        fi
    else
        fail "no ssh-ed25519 key in agent"
    fi

    ssh-add -e "$LIBP11" 2>/dev/null || true
    kill "$AGENT_PID" 2>/dev/null || true; wait "$AGENT_PID" 2>/dev/null || true
else
    echo "SKIP: ssh-agent failed to start" >&2
    exit 77
fi

echo "$PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
