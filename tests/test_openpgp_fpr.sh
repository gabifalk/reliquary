#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Regression test: IMPORT_SLOT derives the OpenPGP v4 key fingerprint.
#
# gpg's keytocard sends the key with a (created-at <unix-seconds>) element but
# no SETATTR KEY-FPR, so the daemon must compute the v4 fingerprint itself --
# otherwise gpg --card-status shows [none] and cannot bind General key info.
# This imports a known rsa4096 key with a created-at and checks the daemon's
# stored fingerprint matches an independent computation.
set -e

DAEMON="$1"
KEYFILE="$2"
if [ -z "$DAEMON" ] || [ -z "$KEYFILE" ]; then
    echo "Usage: $0 <reliquaryd> <fixture_rsa4096.key>" >&2
    exit 1
fi
[ -f "$KEYFILE" ] || { echo "SKIP: key fixture not found at $KEYFILE" >&2; exit 77; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 not found" >&2; exit 77; }

TMPDIR=$(mktemp -d /tmp/test_openpgp_fpr_XXXXXX)
STORE="$TMPDIR/store"; XDG="$TMPDIR/xdg"; SOCK="$XDG/reliquary/socket"; DAEMON_PID=""
cleanup() { [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null; wait 2>/dev/null || true; rm -rf "$TMPDIR"; }
trap cleanup EXIT
mkdir -p "$STORE" "$XDG"
XDG_RUNTIME_DIR="$XDG" "$DAEMON" --store "$STORE" 2>/dev/null &
DAEMON_PID=$!
for i in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "daemon socket did not appear" >&2; exit 1; }

python3 - "$SOCK" "$KEYFILE" <<'PYEOF'
import hashlib, socket, sys

sock_path, keyfile = sys.argv[1], sys.argv[2]
PIN = "1234"
CREATED = 1700000000   # fixed test creation time

def esc(b): return b.replace(b'%', b'%25').replace(b'\r', b'%0D').replace(b'\n', b'%0A')
def unesc(b):
    out = bytearray(); i = 0
    while i < len(b):
        if b[i:i+1] == b'%': out.append(int(b[i+1:i+3], 16)); i += 3
        else: out.append(b[i]); i += 1
    return bytes(out)

class Conn:
    def __init__(self, f): self.f = f
    def send(self, s): self.f.write(s.encode() + b'\n'); self.f.flush()
    def send_data(self, d):
        for i in range(0, max(1, len(d)), 400): self.f.write(b'D ' + esc(d[i:i+400]) + b'\n')
        self.f.write(b'END\n'); self.f.flush()
    def transact(self, cmd, inq=None):
        if cmd is not None: self.send(cmd)
        data = bytearray()
        while True:
            line = self.f.readline().rstrip(b'\r\n')
            if line.startswith(b'D '): data += unesc(line[2:])
            elif line.startswith(b'OK'): return True, bytes(data)
            elif line.startswith(b'ERR'): return False, line.decode()
            elif line.startswith(b'INQUIRE'):
                kw = line[8:].split(b' ')[0].decode()
                a = inq(kw) if inq else None
                self.send_data(a) if a is not None else self.send("CANCEL")

# read a length-prefixed value for token `name` from a canonical S-expression
def sexp_val(sexp, name):
    tag = b'(1:' + name.encode()
    i = sexp.find(tag); assert i >= 0, name
    p = i + len(tag); j = sexp.index(b':', p)
    n = int(sexp[p:j]); return sexp[j+1:j+1+n]

key = open(keyfile, 'rb').read()
# splice "(created-at <CREATED>)" in as the last child of the private-key list
ts = str(CREATED).encode()
ins = b'(10:created-at' + str(len(ts)).encode() + b':' + ts + b')'
assert key.rstrip().endswith(b')')
keydata = key[:-1] + ins + b')'

n = int.from_bytes(sexp_val(key, 'n'), 'big')
e = int.from_bytes(sexp_val(key, 'e'), 'big')

def mpi(x):
    bl = x.bit_length()
    return bytes([bl >> 8, bl & 0xff]) + x.to_bytes((bl + 7) // 8, 'big')
body = b'\x04' + CREATED.to_bytes(4, 'big') + b'\x01' + mpi(n) + mpi(e)
expect = hashlib.sha1(b'\x99' + len(body).to_bytes(2, 'big') + body).hexdigest().upper()

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(sock_path)
d = Conn(s.makefile('rwb', buffering=0))
d.transact(None)
for cmd, inq in [
    ("INIT_STORE adminpin", None),
    ("CREATE_TOKEN tok %s adminpin" % PIN, None),
    ("OPEN_SESSION tok", None),
    ("LOGIN %s" % PIN, None),
    ("IMPORT_SLOT 1 decrypt.rsa-raw", lambda kw: keydata if kw == "KEYDATA" else None),
]:
    ok, r = d.transact(cmd, inq)
    if not ok: print("setup failed: %s -> %s" % (cmd, r)); sys.exit(1)
ok, got = d.transact("GET_ATTRIBUTE fpr.1")
got = got.decode().strip().upper() if ok else "(none)"

if got == expect:
    print("ok: daemon fingerprint %s matches independent computation" % got)
    sys.exit(0)
print("FAIL: daemon fpr=%s expected=%s" % (got, expect))
sys.exit(1)
PYEOF
rc=$?
echo "test_openpgp_fpr: $([ $rc -eq 0 ] && echo PASS || echo FAIL)"
exit $rc
