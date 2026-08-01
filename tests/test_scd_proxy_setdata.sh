#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Regression test: the scd-proxy must reassemble a chunked SETDATA.
#
# A 512-byte rsa4096 ciphertext is 1024 hex chars, past the Assuan line limit,
# so gpg-agent sends it to scdaemon as:
#     SETDATA <first chunk>
#     SETDATA --append <rest>
# cmd_setdata must honour --append and accumulate.  When it did not, only the
# final chunk survived (with a literal "--append" prefix), hex_decode rejected
# it, and PKDECRYPT failed with GPG_ERR_INV_VALUE ("Invalid value") -- the exact
# symptom seen with real rsa4096 keys on a card.
#
# This drives the proxy's Assuan pipe directly (no gpg): import a known rsa4096
# key into the encrypt slot, hand the proxy a raw ciphertext split across
# SETDATA + SETDATA --append, and check the raw-RSA result round-trips.
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

TMPDIR=$(mktemp -d /tmp/test_scd_setdata_XXXXXX)
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
import os, socket, subprocess, sys, secrets

sock_path, proxy_bin, keyfile = sys.argv[1], sys.argv[2], sys.argv[3]
PIN = "1234"

# ---- minimal Assuan line protocol over a byte stream (socket or pipe) ----
def esc(b):   # escape data we SEND on a D line
    return b.replace(b'%', b'%25').replace(b'\r', b'%0D').replace(b'\n', b'%0A')
def unesc(b): # unescape data we RECEIVE on a D line
    out = bytearray(); i = 0
    while i < len(b):
        if b[i:i+1] == b'%' and i + 2 < len(b) + 1:
            out.append(int(b[i+1:i+3], 16)); i += 3
        else:
            out.append(b[i]); i += 1
    return bytes(out)

class Conn:
    def __init__(self, wfile, rfile):
        self.w, self.r = wfile, rfile
    def send(self, line):
        self.w.write(line.encode() + b'\n'); self.w.flush()
    def send_data(self, data):        # answer an inquiry with data + END
        for i in range(0, max(1, len(data)), 400):
            self.w.write(b'D ' + esc(data[i:i+400]) + b'\n')
        self.w.write(b'END\n'); self.w.flush()
    def readline(self):
        return self.r.readline()
    # Run one command; return (ok, dbytes). Answer inquiries via on_inquire(kw)->bytes|None
    def transact(self, cmd, on_inquire=None):
        if cmd is not None:
            self.send(cmd)
        data = bytearray()
        while True:
            raw = self.readline()
            if not raw:
                raise RuntimeError("connection closed waiting for response to %r" % cmd)
            line = raw.rstrip(b'\r\n')
            if line.startswith(b'D '):
                data += unesc(line[2:])
            elif line.startswith(b'OK'):
                return True, bytes(data)
            elif line.startswith(b'ERR'):
                return False, line.decode(errors='replace')
            elif line.startswith(b'INQUIRE'):
                kw = line[8:].split(b' ')[0].decode()
                ans = on_inquire(kw) if on_inquire else None
                if ans is None:
                    self.send("CANCEL");
                else:
                    self.send_data(ans)
            elif line.startswith(b'S ') or line.startswith(b'#'):
                continue
            else:
                continue

def sexp_int(sexp, name):
    # parse "(...(name<len>:<bytes>)...)" canonical S-expression token
    tag = name.encode()
    idx = sexp.find(b'(1:' + tag)  # e.g. (1:n513:....)
    assert idx >= 0, "no %s in pubkey" % name
    p = idx + 3 + len(tag)
    j = sexp.index(b':', p)
    ln = int(sexp[p:j]); start = j + 1
    return int.from_bytes(sexp[start:start+ln], 'big')

# ---- setup: create token + import the rsa4096 key into the encrypt slot ----
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(sock_path)
f = s.makefile('rwb', buffering=0)
d = Conn(f, f)
d.transact(None)  # consume greeting
key_bytes = open(keyfile, 'rb').read()
for cmd, inq in [
    ("INIT_STORE adminpin", None),
    ("CREATE_TOKEN tok %s adminpin" % PIN, None),
    ("OPEN_SESSION tok", None),
    ("LOGIN %s" % PIN, None),
    ("IMPORT_SLOT 1 decrypt.rsa-raw", lambda kw: key_bytes if kw == "KEYDATA" else None),
]:
    ok, r = d.transact(cmd, inq)
    if not ok:
        print("setup step failed: %s -> %s" % (cmd, r)); sys.exit(1)
ok, pub_hex = d.transact("GET_ATTRIBUTE public_key.1"); assert ok, pub_hex
ok, grip_hex = d.transact("GET_ATTRIBUTE keygrip.1");   assert ok, grip_hex
d.transact("CLOSE_SESSION")
pub = bytes.fromhex(pub_hex.decode())
grip = grip_hex.decode().strip()
n = sexp_int(pub, "n"); e = sexp_int(pub, "e")
klen = (n.bit_length() + 7) // 8

# ---- build a raw ciphertext for a known plaintext, then split it ----
P = secrets.randbelow(n - 3) + 2
C = pow(P, e, n)
chex = C.to_bytes(klen, 'big').hex()
assert len(chex) > 952, "ciphertext too short to force chunking (%d)" % len(chex)
c1, c2 = chex[:900], chex[900:]

# ---- drive the proxy over its Assuan pipe ----
env = dict(os.environ, RELIQUARY_SOCKET=sock_path)
proc = subprocess.Popen([proxy_bin], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)
px = Conn(proc.stdin, proc.stdout)
px.transact(None)                 # greeting
px.transact("SERIALNO")           # select the (only) token
ok, _ = px.transact("SETDATA %s" % c1); assert ok, "SETDATA chunk1 failed"
ok, _ = px.transact("SETDATA --append %s" % c2); assert ok, "SETDATA --append failed"
ok, out = px.transact("PKDECRYPT %s" % grip,
                      on_inquire=lambda kw: PIN.encode() if kw == "NEEDPIN" else None)
proc.stdin.close(); proc.terminate()

if not ok:
    print("FAIL: PKDECRYPT errored: %s" % out)
    print("      (this is the bug: chunked SETDATA was not reassembled)")
    sys.exit(1)
# raw RSA decrypt returns P as a big-endian integer (leading zeros dropped)
got = int.from_bytes(out, 'big')
if got == P:
    print("ok: chunked SETDATA reassembled; raw rsa4096 decrypt round-tripped")
    sys.exit(0)
print("FAIL: round-trip mismatch: got 0x%x want 0x%x" % (got, P))
sys.exit(1)
PYEOF
rc=$?
echo "test_scd_proxy_setdata: $([ $rc -eq 0 ] && echo PASS || echo FAIL)"
exit $rc
