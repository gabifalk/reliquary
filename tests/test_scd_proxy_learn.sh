#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Regression test: scd-proxy LEARN must not report a keygrip as a fingerprint.
#
# cmd_learn emits a KEY-FPR status line per key.  When a slot has no OpenPGP
# fingerprint (e.g. a key imported without keytocard's SET_ATTRIBUTE KEY-FPR),
# the proxy used to fall back to the *keygrip* ("hf ? fpr : grip").  A keygrip
# is a different SHA-1 (over the public-key S-expression, not the key packet),
# so gpg could not map the card key to its keyring key -- "gpg --card-status"
# printed keygrips in the fingerprint fields and "General key info: [none]".
#
# The KEYPAIRINFO keygrip must still be correct; the KEY-FPR line for a
# fingerprint-less slot must simply be omitted (never equal to the keygrip).
set -e

DAEMON="$1"
SCD_PROXY="$2"
KEYFILE="$3"

if [ -z "$DAEMON" ] || [ -z "$SCD_PROXY" ] || [ -z "$KEYFILE" ]; then
    echo "Usage: $0 <reliquaryd> <reliquary-scd-proxy> <fixture_rsa4096.key>" >&2
    exit 1
fi
[ -f "$KEYFILE" ] || { echo "SKIP: key fixture not found at $KEYFILE" >&2; exit 77; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 not found" >&2; exit 77; }

TMPDIR=$(mktemp -d /tmp/test_scd_learn_XXXXXX)
STORE="$TMPDIR/store"
XDG="$TMPDIR/xdg"
SOCK="$XDG/reliquary/socket"
DAEMON_PID=""
cleanup() {
    [ -n "$DAEMON_PID" ] && { kill "$DAEMON_PID" 2>/dev/null || true; }
    wait 2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

mkdir -p "$STORE" "$XDG"
XDG_RUNTIME_DIR="$XDG" "$DAEMON" --store "$STORE" 2>/dev/null &
DAEMON_PID=$!
for i in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "daemon socket did not appear" >&2; exit 1; }

RELIQUARY_SOCKET="$SOCK" python3 - "$SOCK" "$SCD_PROXY" "$KEYFILE" <<'PYEOF'
import os, socket, subprocess, sys

sock_path, proxy_bin, keyfile = sys.argv[1], sys.argv[2], sys.argv[3]
PIN = "1234"

def esc(b):
    return b.replace(b'%', b'%25').replace(b'\r', b'%0D').replace(b'\n', b'%0A')

class Conn:
    def __init__(self, wfile, rfile):
        self.w, self.r = wfile, rfile
    def send(self, line):
        self.w.write(line.encode() + b'\n'); self.w.flush()
    def send_data(self, data):
        for i in range(0, max(1, len(data)), 400):
            self.w.write(b'D ' + esc(data[i:i+400]) + b'\n')
        self.w.write(b'END\n'); self.w.flush()
    # returns (ok, dbytes, status_lines). Answers inquiries via on_inquire.
    def transact(self, cmd, on_inquire=None):
        if cmd is not None:
            self.send(cmd)
        data = bytearray(); status = []
        while True:
            raw = self.r.readline()
            if not raw:
                raise RuntimeError("closed waiting on %r" % cmd)
            line = raw.rstrip(b'\r\n')
            if line.startswith(b'D '):
                data += line[2:]
            elif line.startswith(b'S '):
                status.append(line[2:].decode(errors='replace'))
            elif line.startswith(b'OK'):
                return True, bytes(data), status
            elif line.startswith(b'ERR'):
                return False, line.decode(errors='replace'), status
            elif line.startswith(b'INQUIRE'):
                kw = line[8:].split(b' ')[0].decode()
                ans = on_inquire(kw) if on_inquire else None
                if ans is None: self.send("CANCEL")
                else: self.send_data(ans)

# ---- setup: token + import rsa4096 key into encrypt slot (no fpr set) ----
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(sock_path)
f = s.makefile('rwb', buffering=0)
d = Conn(f, f)
d.transact(None)
key_bytes = open(keyfile, 'rb').read()
for cmd, inq in [
    ("INIT_STORE adminpin", None),
    ("CREATE_TOKEN tok %s adminpin" % PIN, None),
    ("OPEN_SESSION tok", None),
    ("LOGIN %s" % PIN, None),
    ("IMPORT_SLOT 1 decrypt.rsa-raw", lambda kw: key_bytes if kw == "KEYDATA" else None),
]:
    ok, r, _ = d.transact(cmd, inq)
    if not ok:
        print("setup step failed: %s -> %s" % (cmd, r)); sys.exit(1)
ok, grip_hex, _ = d.transact("GET_ATTRIBUTE keygrip.1"); assert ok, grip_hex
d.transact("CLOSE_SESSION")
grip = grip_hex.decode().strip().upper()

# ---- drive the proxy's LEARN and inspect the status lines ----
env = dict(os.environ, RELIQUARY_SOCKET=sock_path)
proc = subprocess.Popen([proxy_bin], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)
px = Conn(proc.stdin, proc.stdout)
px.transact(None)
px.transact("SERIALNO")
ok_l, _, learn_status = px.transact("LEARN")
ok_g, _, getattr_status = px.transact("GETATTR KEY-FPR")
proc.stdin.close(); proc.terminate()
if not ok_l:
    print("FAIL: LEARN errored"); sys.exit(1)
if not ok_g:
    print("FAIL: GETATTR KEY-FPR errored"); sys.exit(1)

keypairinfo = [s for s in learn_status if s.startswith("KEYPAIRINFO")]

# The encrypt slot's keygrip must be reported (via KEYPAIRINFO), correctly.
if not any(grip in s.upper() for s in keypairinfo):
    print("FAIL: encrypt-slot keygrip %s missing from KEYPAIRINFO: %s" % (grip, keypairinfo))
    sys.exit(1)

# No KEY-FPR line, from LEARN or from GETATTR, may carry the keygrip
# masquerading as a fingerprint.
for src, lines in (("LEARN", learn_status), ("GETATTR", getattr_status)):
    bad = [s for s in lines if s.startswith("KEY-FPR") and grip in s.upper()]
    if bad:
        print("FAIL: %s reports the keygrip as a KEY-FPR fingerprint: %s" % (src, bad))
        sys.exit(1)

print("ok: keygrip via KEYPAIRINFO; no bogus KEY-FPR from LEARN or GETATTR")
sys.exit(0)
PYEOF
rc=$?
echo "test_scd_proxy_learn: $([ $rc -eq 0 ] && echo PASS || echo FAIL)"
exit $rc
