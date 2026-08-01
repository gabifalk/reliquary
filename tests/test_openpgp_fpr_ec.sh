#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Regression test: IMPORT_SLOT derives correct OpenPGP v4 fingerprints for EC
# keys (EdDSA, ECDSA and ECDH incl. the curve-specific KDF parameters), checked
# against gpg's own fingerprints after keytocard.
#
#   ed25519 : cert primary + sign + auth subkeys -> slots 0,2 (EdDSA, algo 22)
#   nistp256: sign primary (ECDSA, algo 19) -> slot 0
#             + encr subkey (ECDH, algo 18, KDF) -> slot 1
#
# We read the fingerprints the daemon stored and compare them to gpg's, which is
# the authoritative source.  The generic RSA path is covered by test_openpgp_fpr.
set -e

DAEMON="$1"
SCD_PROXY="$2"
if [ -z "$DAEMON" ] || [ -z "$SCD_PROXY" ]; then
    echo "Usage: $0 <reliquaryd> <reliquary-scd-proxy>" >&2
    exit 1
fi
for cmd in gpg gpg-agent gpgconf python3; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "SKIP: $cmd not found" >&2; exit 77; }
done
# Need EC support in this gpg build.
if ! gpg --version 2>/dev/null | grep -qiE "cv25519|ed25519|nistp256|Pubkey.*ECDH"; then
    :  # older --version listings vary; the keygen below will SKIP on failure
fi

FAILED=0

make_token_and_check() {
    KIND="$1"          # ed | nist
    TMPDIR=$(mktemp -d /tmp/test_fpr_ec_XXXXXX)
    STORE="$TMPDIR/store"; XDG="$TMPDIR/xdg"; SOCK="$XDG/reliquary/socket"
    GNUPGHOME="$TMPDIR/gnupg"; PIN="testpin1234"; DAEMON_PID=""
    mkdir -p "$STORE" "$XDG" "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
    XDG_RUNTIME_DIR="$XDG" "$DAEMON" --store "$STORE" 2>/dev/null &
    DAEMON_PID=$!
    for i in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
    if [ ! -S "$SOCK" ]; then echo "  $KIND: daemon socket did not appear" >&2; FAILED=1; return; fi
    export RELIQUARY_SOCKET="$SOCK" GNUPGHOME

    python3 - "$SOCK" gpgkey "$PIN" <<'PYEOF'
import socket, sys, time
sp, label, pin = sys.argv[1], sys.argv[2], sys.argv[3]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(sp)
def ok():
    b=b''
    while True:
        b+=s.recv(4096)
        for l in b.split(b'\n'):
            if l.startswith(b'OK'): return True
            if l.startswith(b'ERR'): return False
        time.sleep(0.05)
ok(); s.sendall(b"INIT_STORE adminpin\n"); ok()
s.sendall(f"CREATE_TOKEN {label} {pin} adminpin\n".encode()); ok()
s.sendall(b"CLOSE_SESSION\n"); ok(); s.close()
PYEOF

    WRAP="$TMPDIR/w.sh"
    printf '#!/bin/sh\nexport RELIQUARY_SOCKET="%s"\nexec "%s" "$@" 2>/dev/null\n' "$SOCK" "$SCD_PROXY" > "$WRAP"
    chmod +x "$WRAP"
    printf 'scdaemon-program %s\nallow-loopback-pinentry\n' "$WRAP" > "$GNUPGHOME/gpg-agent.conf"
    gpg-agent --homedir "$GNUPGHOME" --daemon 2>/dev/null || true
    sleep 0.3
    g() { gpg --homedir "$GNUPGHOME" --batch --passphrase "" --pinentry-mode loopback "$@"; }

    if [ "$KIND" = ed ]; then
        g --quick-gen-key "Ed <t@test>" ed25519 cert 0 2>/dev/null
        FPR=$(g --with-colons -k 2>/dev/null | awk -F: '/^fpr/{print $10; exit}')
        [ -z "$FPR" ] && { echo "  ed: SKIP (no ed25519 support)"; kill $DAEMON_PID 2>/dev/null; rm -rf "$TMPDIR"; return; }
        g --quick-add-key "$FPR" ed25519 sign 0 2>/dev/null
        g --quick-add-key "$FPR" ed25519 auth 0 2>/dev/null
        KTC='key 1\nkeytocard\n1\nkey 1\nkey 2\nkeytocard\n3\nsave\n'
        SLOTS="0:s 2:a"
    else
        g --quick-gen-key "N <t@test>" nistp256 sign 0 2>/dev/null
        FPR=$(g --with-colons -k 2>/dev/null | awk -F: '/^fpr/{print $10; exit}')
        [ -z "$FPR" ] && { echo "  nist: SKIP (no nistp256 support)"; kill $DAEMON_PID 2>/dev/null; rm -rf "$TMPDIR"; return; }
        g --quick-add-key "$FPR" nistp256 encr 0 2>/dev/null
        KTC='keytocard\ny\n1\nkey 1\nkeytocard\n2\nsave\n'   # primary(ECDSA)->slot0, encr(ECDH)->slot1
        SLOTS="0:primary 1:e"
    fi
    printf "$KTC" | gpg --homedir "$GNUPGHOME" --no-tty --pinentry-mode loopback \
        --passphrase "$PIN" --command-fd 0 --edit-key "$FPR" 2>/dev/null || true

    # gpg's per-capability fingerprints
    g --with-colons -k 2>/dev/null | awk -F: '/^sub/{c=$12} /^fpr/{print c, $10}' > "$TMPDIR/gf"
    META="$STORE/gpgkey/metadata"
    for pair in $SLOTS; do
        sl=${pair%:*}; cap=${pair#*:}
        if [ "$cap" = primary ]; then exp="$FPR"; else exp=$(awk -v c="$cap" '$1==c{print $2}' "$TMPDIR/gf"); fi
        tok=$(grep -oE "slot-$sl-key-fpr [^)]*" "$META" | sed -E 's/slot-.-key-fpr //; s/[" ]//g')
        if [ -n "$exp" ] && [ "$exp" = "$tok" ]; then
            echo "  $KIND slot$sl: ok ($tok)"
        else
            echo "  $KIND slot$sl: FAIL exp=$exp tok=$tok"; FAILED=1
        fi
    done
    gpgconf --homedir "$GNUPGHOME" --kill gpg-agent 2>/dev/null || true
    kill $DAEMON_PID 2>/dev/null || true; wait 2>/dev/null || true
    rm -rf "$TMPDIR"
}

echo "test_openpgp_fpr_ec:"
make_token_and_check ed
make_token_and_check nist
[ "$FAILED" -eq 0 ] && { echo "PASS"; exit 0; } || { echo "FAIL"; exit 1; }
