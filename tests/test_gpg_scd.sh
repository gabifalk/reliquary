#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Integration test: exercise reliquary scd-proxy infrastructure, multi-token
# SWITCHCARD, and gpg sign/decrypt via inline NEEDPIN.
set -e

DAEMON="$1"
SCD_PROXY="$2"
FIXTURE_KEY="$3"

if [ -z "$DAEMON" ] || [ -z "$SCD_PROXY" ] || [ -z "$FIXTURE_KEY" ]; then
    echo "Usage: $0 <reliquaryd> <reliquary-scd-proxy> <fixture_key.gpg>" >&2
    exit 1
fi

if [ ! -f "$FIXTURE_KEY" ]; then
    echo "SKIP: fixture key not found at $FIXTURE_KEY" >&2
    exit 77
fi

for cmd in gpg-connect-agent gpg-agent gpg python3; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo "SKIP: $cmd not found" >&2
        exit 77
    }
done

TMPDIR=$(mktemp -d /tmp/test_gpg_scd_XXXXXX)
STORE="$TMPDIR/store"
XDG="$TMPDIR/xdg"
SOCK="$XDG/reliquary/socket"
GNUPGHOME="$TMPDIR/gnupg"
PIN="testpin1234"
DAEMON_PID=""

cleanup() {
    gpgconf --homedir "$GNUPGHOME" --kill gpg-agent 2>/dev/null || true
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

mkdir -p "$STORE" "$XDG" "$GNUPGHOME"
chmod 700 "$GNUPGHOME"

XDG_RUNTIME_DIR="$XDG" "$DAEMON" --store "$STORE" 2>/dev/null &
DAEMON_PID=$!

for i in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "daemon socket did not appear" >&2; exit 1; }

export RELIQUARY_SOCKET="$SOCK"
export GNUPGHOME

# --- create a token ---

create_token() {
    python3 - "$SOCK" "$@" <<'PYEOF'
import socket, sys, time
sock_path, label, pin = sys.argv[1], sys.argv[2], sys.argv[3]
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

# CLOSE_SESSION
s.sendall(b"CLOSE_SESSION\n")
read_ok(s)

s.close()
sys.exit(0)
PYEOF
}

# --- configure gpg-agent to use scd-proxy ---

# gpg-agent doesn't pass env to scdaemon, so wrap the proxy
WRAPPER="$TMPDIR/scd-wrapper.sh"
cat > "$WRAPPER" <<WEOF
#!/bin/sh
export RELIQUARY_SOCKET="$SOCK"
exec "$SCD_PROXY" "\$@" 2>"$TMPDIR/proxy.log"
WEOF
chmod +x "$WRAPPER"

cat > "$GNUPGHOME/gpg-agent.conf" <<CONF
scdaemon-program $WRAPPER
allow-loopback-pinentry
CONF

gpg-agent --homedir "$GNUPGHOME" --daemon --log-file "$TMPDIR/agent.log" 2>/dev/null || true
sleep 0.5

# Helper to send scd commands via gpg-connect-agent
scd_cmd() {
    local result
    result=$(gpg-connect-agent --homedir "$GNUPGHOME" "SCD $1" /bye 2>&1)
    # Dump agent log on error
    if echo "$result" | grep -q "ERR"; then
        echo "--- agent log tail ---" >&2
        tail -10 "$TMPDIR/agent.log" >&2
    fi
    echo "$result"
}

# --- tests ---

echo "test_gpg_scd:"

run_test "create_token"
if create_token "gpgkey" "$PIN"; then ok; else fail "create"; fi

# We need to open session + login via the proxy before scdaemon commands work.
# gpg-connect-agent talks to gpg-agent, which talks to scd-proxy, which talks to daemon.

# First, open session and login through the proxy
run_test "scd_open_session"
OUT=$(scd_cmd "OPEN_SESSION gpgkey" 2>&1)
if echo "$OUT" | grep -q "^OK"; then
    ok
else
    echo "$OUT" >&2
    fail "OPEN_SESSION"
fi

run_test "scd_login"
OUT=$(scd_cmd "LOGIN $PIN" 2>&1)
if echo "$OUT" | grep -q "^OK"; then
    ok
else
    echo "$OUT" >&2
    fail "LOGIN"
fi

# SERIALNO
run_test "scd_serialno"
OUT=$(scd_cmd "SERIALNO" 2>&1)
if echo "$OUT" | grep -q "^S SERIALNO"; then
    ok
else
    echo "$OUT" >&2
    fail "SERIALNO"
fi

# LEARN (empty token -- should still report SERIALNO and KEY-ATTR)
run_test "scd_learn"
OUT=$(scd_cmd "LEARN" 2>&1)
if echo "$OUT" | grep -q "KEY-ATTR\|SERIALNO"; then
    ok
else
    echo "$OUT" >&2
    fail "LEARN"
fi

# GETATTR SERIALNO
run_test "scd_getattr_serialno"
OUT=$(scd_cmd "GETATTR SERIALNO" 2>&1)
if echo "$OUT" | grep -q "^S SERIALNO"; then
    ok
else
    echo "$OUT" >&2
    fail "GETATTR SERIALNO"
fi

# GETATTR KEY-ATTR (empty token returns defaults)
run_test "scd_getattr_keyattr"
OUT=$(scd_cmd "GETATTR KEY-ATTR" 2>&1)
if echo "$OUT" | grep -q "rsa"; then
    ok
else
    echo "$OUT" >&2
    fail "GETATTR KEY-ATTR"
fi

# --- keytocard: import fixture key and move all 3 subkeys to token ---

gpg --homedir "$GNUPGHOME" --batch --passphrase "" --pinentry-mode loopback \
    --import "$FIXTURE_KEY" 2>/dev/null

FPR=$(gpg --homedir "$GNUPGHOME" --with-colons --list-keys 2>/dev/null \
    | grep '^fpr' | head -1 | cut -d: -f10)

if [ -z "$FPR" ]; then
    echo "ERROR: failed to import fixture key" >&2
    exit 1
fi

echo "$FPR:6:" | gpg --homedir "$GNUPGHOME" --import-ownertrust 2>/dev/null

run_test "keytocard_all"
printf 'key 1\nkeytocard\n1\nkey 1\nkey 2\nkeytocard\n2\nkey 2\nkey 3\nkeytocard\n3\nkey 3\nsave\n' \
    | gpg --homedir "$GNUPGHOME" --no-tty --pinentry-mode loopback \
    --passphrase "" --command-fd 0 --status-fd 2 \
    --edit-key "$FPR" 2>"$TMPDIR/keytocard.err" || true
if grep -q "update failed\|SC_OP_FAILURE" "$TMPDIR/keytocard.err" 2>/dev/null; then
    cat "$TMPDIR/keytocard.err" >&2
    echo "--- proxy log ---" >&2
    cat "$TMPDIR/proxy.log" >&2
    fail "keytocard"
else
    ok
fi

# --- crypto tests (gpg -> gpg-agent -> proxy -> daemon) ---

run_test "gpg_sign_verify"
if echo "test payload" | gpg --homedir "$GNUPGHOME" --batch --pinentry-mode loopback \
    --passphrase "$PIN" --local-user "$FPR" --sign 2>"$TMPDIR/sign.err" \
    | gpg --homedir "$GNUPGHOME" --batch --verify 2>"$TMPDIR/verify.err"; then
    ok
else
    cat "$TMPDIR/sign.err" >&2
    cat "$TMPDIR/verify.err" >&2
    fail "sign+verify"
fi

run_test "gpg_encrypt_decrypt"
PLAIN="decrypt round-trip test"
DECRYPTED=$(echo "$PLAIN" | gpg --homedir "$GNUPGHOME" --batch --trust-model always \
    --recipient "$FPR" --encrypt 2>"$TMPDIR/enc.err" \
    | gpg --homedir "$GNUPGHOME" --batch --pinentry-mode loopback \
    --passphrase "$PIN" --decrypt 2>"$TMPDIR/dec.err")
if [ "$DECRYPTED" = "$PLAIN" ]; then
    ok
else
    echo "expected: $PLAIN" >&2
    echo "got: $DECRYPTED" >&2
    cat "$TMPDIR/enc.err" >&2
    cat "$TMPDIR/dec.err" >&2
    fail "encrypt+decrypt"
fi

run_test "gpg_readkey_auth"
OUT=$(scd_cmd "READKEY OPENPGP.3")
if echo "$OUT" | grep -q "^D "; then
    ok
else
    echo "$OUT" >&2
    fail "READKEY OPENPGP.3"
fi

# --- multi-token SWITCHCARD tests ---

# Capture serial for first token
SERIAL1=$(scd_cmd "SERIALNO" 2>&1 | grep "^S SERIALNO" | head -1 | awk '{print $3}')

# Create a second token
run_test "create_token2"
if create_token "gpgkey2" "$PIN"; then ok; else fail "create2"; fi

# Open the second token to learn its serial
run_test "scd_open_session2"
OUT=$(scd_cmd "OPEN_SESSION gpgkey2" 2>&1)
if echo "$OUT" | grep -q "^OK"; then ok; else echo "$OUT" >&2; fail "OPEN_SESSION2"; fi

SERIAL2=$(scd_cmd "SERIALNO" 2>&1 | grep "^S SERIALNO" | head -1 | awk '{print $3}')

# GETINFO card_list should return two SERIALNO lines
run_test "scd_getinfo_card_list"
OUT=$(scd_cmd "GETINFO card_list" 2>&1)
COUNT=$(echo "$OUT" | grep -c "^S SERIALNO")
if [ "$COUNT" -ge 2 ]; then
    ok
else
    echo "$OUT" >&2
    fail "expected >=2 SERIALNO lines, got $COUNT"
fi

# Switch to second token
run_test "scd_switchcard_to_token2"
OUT=$(scd_cmd "SWITCHCARD $SERIAL2" 2>&1)
if echo "$OUT" | grep -q "^S SERIALNO.*$SERIAL2"; then
    ok
else
    echo "$OUT" >&2
    fail "SWITCHCARD to token2"
fi

# Confirm with SERIALNO
run_test "scd_serialno_after_switch2"
OUT=$(scd_cmd "SERIALNO" 2>&1)
if echo "$OUT" | grep -q "$SERIAL2"; then
    ok
else
    echo "$OUT" >&2
    fail "SERIALNO after switch to token2"
fi

# Switch back to first token
run_test "scd_switchcard_to_token1"
OUT=$(scd_cmd "SWITCHCARD $SERIAL1" 2>&1)
if echo "$OUT" | grep -q "^S SERIALNO.*$SERIAL1"; then
    ok
else
    echo "$OUT" >&2
    fail "SWITCHCARD to token1"
fi

# Confirm with SERIALNO
run_test "scd_serialno_after_switch1"
OUT=$(scd_cmd "SERIALNO" 2>&1)
if echo "$OUT" | grep -q "$SERIAL1"; then
    ok
else
    echo "$OUT" >&2
    fail "SERIALNO after switch to token1"
fi

# --- SERIALNO --demand selects a specific card (gpg --card-status all path) ---
# `gpg --card-status all` iterates multiple cards by issuing
# "SCD SERIALNO --demand=<serial>" for each (g10/card-util.c card_status),
# NOT SWITCHCARD. The proxy must honor --demand or every card after the first
# reports the first card's Application ID -- the same card shown twice.
# current_label is token1 here, so demanding token2 must actually switch.
run_test "scd_serialno_demand_token2"
OUT=$(scd_cmd "SERIALNO --demand=$SERIAL2" 2>&1)
if echo "$OUT" | grep -q "^S SERIALNO.*$SERIAL2"; then
    ok
else
    echo "$OUT" >&2
    fail "SERIALNO --demand did not select token2 (got: $OUT)"
fi

# The session must be genuinely re-pointed: a plain GETATTR SERIALNO (which
# resolves against the daemon's open session) must now reflect token2.
run_test "scd_getattr_serialno_after_demand2"
OUT=$(scd_cmd "GETATTR SERIALNO" 2>&1)
if echo "$OUT" | grep -q "$SERIAL2"; then
    ok
else
    echo "$OUT" >&2
    fail "GETATTR SERIALNO after --demand=token2 still shows the old card"
fi

# Demanding token1 again must switch back (end on token1 for the sign test).
run_test "scd_serialno_demand_token1"
OUT=$(scd_cmd "SERIALNO --demand=$SERIAL1" 2>&1)
if echo "$OUT" | grep -q "^S SERIALNO.*$SERIAL1"; then
    ok
else
    echo "$OUT" >&2
    fail "SERIALNO --demand did not select token1 (got: $OUT)"
fi

# Sign after SWITCHCARD (session was reset by switch, so NEEDPIN triggers again)
run_test "gpg_sign_after_switchcard"
if echo "test after switch" | gpg --homedir "$GNUPGHOME" --batch --pinentry-mode loopback \
    --passphrase "$PIN" --local-user "$FPR" --sign 2>"$TMPDIR/sign2.err" \
    | gpg --homedir "$GNUPGHOME" --batch --verify 2>"$TMPDIR/verify2.err"; then
    ok
else
    cat "$TMPDIR/sign2.err" >&2
    cat "$TMPDIR/verify2.err" >&2
    fail "sign after switchcard"
fi

# LOGOUT
run_test "scd_logout"
OUT=$(scd_cmd "LOGOUT" 2>&1)
if echo "$OUT" | grep -q "^OK"; then
    ok
else
    echo "$OUT" >&2
    fail "LOGOUT"
fi

echo "$PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
