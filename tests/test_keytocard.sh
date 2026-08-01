#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Integration test: keytocard for a specific combination of subkey slots.
# Invoked once per combination by meson; each invocation gets its own daemon.
#
# Usage: test_keytocard.sh <reliquaryd> <scd-proxy> <fixture_key.gpg> <name> <subkey...>
#   subkey: sign | encr | auth
set -e

DAEMON="$1"
SCD_PROXY="$2"
FIXTURE_KEY="$3"
COMBO_NAME="$4"
shift 4
SUBKEYS="$*"

if [ -z "$DAEMON" ] || [ -z "$SCD_PROXY" ] || [ -z "$FIXTURE_KEY" ] || [ -z "$COMBO_NAME" ] || [ -z "$SUBKEYS" ]; then
    echo "Usage: $0 <reliquaryd> <scd-proxy> <fixture_key.gpg> <name> <subkey...>" >&2
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

TMPDIR=$(mktemp -d /tmp/test_keytocard_XXXXXX)
STORE="$TMPDIR/store"
XDG="$TMPDIR/xdg"
SOCK="$XDG/reliquary/socket"
GNUPGHOME="$TMPDIR/gnupg"
PIN="testpin1234"
DAEMON_PID=""
TOOL="$(dirname "$SCD_PROXY")/reliquary-tool"

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

# --- create token ---

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

if not read_ok(s):
    sys.exit(1)
s.sendall(b"INIT_STORE adminpin\n")
read_ok(s)
s.sendall(f"CREATE_TOKEN {label} {pin} adminpin\n".encode())
if not read_ok(s):
    s.close(); sys.exit(1)
s.sendall(b"CLOSE_SESSION\n")
read_ok(s)
s.close()
sys.exit(0)
PYEOF
}

TOKEN_LABEL="ktc_$COMBO_NAME"

run_test "create_token"
if create_token "$TOKEN_LABEL" "$PIN"; then ok; else fail "create_token"; fi

# --- configure gpg-agent to use scd-proxy ---
# Must be done BEFORE any gpg command, because gpg auto-starts gpg-agent
# and we need the agent to have the scdaemon-program config from the start.

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

# --- import fixture key ---

gpg --homedir "$GNUPGHOME" --batch --passphrase "" --pinentry-mode loopback \
    --import "$FIXTURE_KEY" 2>/dev/null

FPR=$(gpg --homedir "$GNUPGHOME" --with-colons --list-keys 2>/dev/null \
    | grep '^fpr' | head -1 | cut -d: -f10)

if [ -z "$FPR" ]; then
    echo "ERROR: failed to import fixture key" >&2
    exit 1
fi

# Trust the key
echo "$FPR:6:" | gpg --homedir "$GNUPGHOME" --import-ownertrust 2>/dev/null

gpg-agent --homedir "$GNUPGHOME" --daemon --log-file "$TMPDIR/agent.log" 2>/dev/null || true
sleep 0.5

scd_cmd() {
    gpg-connect-agent --homedir "$GNUPGHOME" "SCD $1" /bye 2>&1
}

# --- open session + login ---

run_test "open_session"
OUT=$(scd_cmd "OPEN_SESSION $TOKEN_LABEL")
if echo "$OUT" | grep -q "^OK"; then ok; else echo "$OUT" >&2; fail "OPEN_SESSION"; fi

run_test "login"
OUT=$(scd_cmd "LOGIN $PIN")
if echo "$OUT" | grep -q "^OK"; then ok; else echo "$OUT" >&2; fail "LOGIN"; fi

# --- keytocard ---
# The fixture has: primary (cert), sub1 (sign), sub2 (encr), sub3 (auth)
# For each subkey, select it, keytocard to the right slot, deselect.
# Slot mapping:
#   sign subkey (key 1) -> slot 1 (Signature key)
#   encr subkey (key 2) -> slot 2 (Encryption key)
#   auth subkey (key 3) -> slot 3 (Authentication key)

build_keytocard_cmds() {
    for sub in $SUBKEYS; do
        case "$sub" in
            sign)
                printf 'key 1\nkeytocard\n1\nkey 1\n'
                ;;
            encr)
                printf 'key 2\nkeytocard\n2\nkey 2\n'
                ;;
            auth)
                printf 'key 3\nkeytocard\n3\nkey 3\n'
                ;;
        esac
    done
    printf 'save\n'
}

run_test "keytocard [$SUBKEYS]"
CMDS=$(build_keytocard_cmds)
echo "$CMDS" | gpg --homedir "$GNUPGHOME" --no-tty --pinentry-mode loopback \
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

# --- verify slots with reliquary-tool ---

if [ -x "$TOOL" ]; then
    run_test "verify_slots"
    INFO=$("$TOOL" info "$TOKEN_LABEL" 2>&1)
    SLOTS_OK=true
    for sub in $SUBKEYS; do
        case "$sub" in
            sign)
                if ! echo "$INFO" | grep -q "sign:.*rsa"; then SLOTS_OK=false; fi
                ;;
            encr)
                if ! echo "$INFO" | grep -q "encrypt:.*rsa"; then SLOTS_OK=false; fi
                ;;
            auth)
                if ! echo "$INFO" | grep -q "auth:.*rsa"; then SLOTS_OK=false; fi
                ;;
        esac
    done
    if $SLOTS_OK; then ok; else echo "$INFO" >&2; fail "slots"; fi
fi

# --- verify operations ---

for sub in $SUBKEYS; do
    case "$sub" in
        sign)
            run_test "sign_verify"
            if echo "test payload" | gpg --homedir "$GNUPGHOME" --batch --pinentry-mode loopback \
                --passphrase "" --local-user "$FPR" --sign 2>"$TMPDIR/sign.err" \
                | gpg --homedir "$GNUPGHOME" --batch --verify 2>"$TMPDIR/verify.err"; then
                ok
            else
                cat "$TMPDIR/sign.err" >&2
                cat "$TMPDIR/verify.err" >&2
                fail "sign+verify"
            fi
            ;;
        encr)
            run_test "encrypt_decrypt"
            PLAIN="decrypt round-trip test"
            DECRYPTED=$(echo "$PLAIN" | gpg --homedir "$GNUPGHOME" --batch --trust-model always \
                --recipient "$FPR" --encrypt 2>"$TMPDIR/enc.err" \
                | gpg --homedir "$GNUPGHOME" --batch --pinentry-mode loopback \
                --passphrase "" --decrypt 2>"$TMPDIR/dec.err")
            if [ "$DECRYPTED" = "$PLAIN" ]; then
                ok
            else
                echo "expected: $PLAIN" >&2
                echo "got: $DECRYPTED" >&2
                cat "$TMPDIR/enc.err" >&2
                cat "$TMPDIR/dec.err" >&2
                fail "encrypt+decrypt"
            fi
            ;;
        auth)
            run_test "readkey_auth"
            OUT=$(scd_cmd "READKEY OPENPGP.3")
            if echo "$OUT" | grep -q "^D "; then
                ok
            else
                echo "$OUT" >&2
                fail "READKEY OPENPGP.3"
            fi
            ;;
    esac
done

echo ""
echo "keytocard_$COMBO_NAME: $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
