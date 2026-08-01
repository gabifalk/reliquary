#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# One-time helper: generate the fixture key used by test_gpg_scd.sh
# Output: tests/data/fixture_key.gpg
#
# Key structure (all rsa2048, no passphrase):
#   Primary  -- cert only
#   Subkey 1 -- sign
#   Subkey 2 -- encr
#   Subkey 3 -- auth
set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
OUTFILE="$SCRIPT_DIR/data/fixture_key.gpg"

TMPDIR=$(mktemp -d /tmp/gen_fixture_XXXXXX)
cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

export GNUPGHOME="$TMPDIR/gnupg"
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"

# Generate cert-only primary key
gpg --homedir "$GNUPGHOME" --batch --passphrase "" --pinentry-mode loopback \
    --quick-gen-key "Fixture <fixture@test>" rsa2048 cert 0 2>/dev/null

FPR=$(gpg --homedir "$GNUPGHOME" --with-colons --list-keys 2>/dev/null \
    | grep '^fpr' | head -1 | cut -d: -f10)

if [ -z "$FPR" ]; then
    echo "ERROR: failed to generate primary key" >&2
    exit 1
fi

# Add sign subkey
gpg --homedir "$GNUPGHOME" --batch --passphrase "" --pinentry-mode loopback \
    --quick-add-key "$FPR" rsa2048 sign 0 2>/dev/null

# Add encr subkey
gpg --homedir "$GNUPGHOME" --batch --passphrase "" --pinentry-mode loopback \
    --quick-add-key "$FPR" rsa2048 encr 0 2>/dev/null

# Add auth subkey
gpg --homedir "$GNUPGHOME" --batch --passphrase "" --pinentry-mode loopback \
    --quick-add-key "$FPR" rsa2048 auth 0 2>/dev/null

# Verify structure
echo "Generated key:"
gpg --homedir "$GNUPGHOME" --list-keys --with-colons 2>/dev/null | grep -E '^(pub|sub|fpr|uid):'

# Export secret keys (includes all subkeys)
mkdir -p "$(dirname "$OUTFILE")"
gpg --homedir "$GNUPGHOME" --batch --passphrase "" --pinentry-mode loopback \
    --export-secret-keys "$FPR" > "$OUTFILE"

echo "Fixture key written to $OUTFILE ($(wc -c < "$OUTFILE") bytes)"
