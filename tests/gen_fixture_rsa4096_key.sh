#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# One-time helper: generate the RSA-4096 fixture private key used by the
# DECRYPT-wire regression test (tests/test_daemon_integration.c:
# test_decrypt_rsa4096_wire). RSA-4096 keygen is slow, so this key is
# generated ONCE, offline, and the result is committed as
# tests/data/fixture_rsa4096.key -- a canonical (GCRYSEXP_FMT_CANON) gcrypt
# S-expression, the exact same format crypto_rsa_keygen() in src/crypto_rsa.c
# produces and that IMPORT_SLOT (cmd_admin.c:cmd_import_slot) accepts.
#
# Output: tests/data/fixture_rsa4096.key
set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
OUTFILE="$SCRIPT_DIR/data/fixture_rsa4096.key"

TMPDIR=$(mktemp -d /tmp/gen_fixture_rsa4096_XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT

cat > "$TMPDIR/genkey.c" <<'EOF'
/* Throwaway generator: mirrors crypto_rsa_keygen() in src/crypto_rsa.c. */
#include <gcrypt.h>
#include <stdio.h>
#include <stdlib.h>

int
main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s outfile\n", argv[0]);
		return 1;
	}
	if (!gcry_check_version(NULL)) {
		fprintf(stderr, "gcry_check_version failed\n");
		return 1;
	}
	gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

	gcry_sexp_t params = NULL, keypair = NULL;
	if (gcry_sexp_build(&params, NULL, "(genkey (rsa (nbits %u)))", 4096u)) {
		fprintf(stderr, "gcry_sexp_build failed\n");
		return 1;
	}
	if (gcry_pk_genkey(&keypair, params)) {
		fprintf(stderr, "gcry_pk_genkey failed\n");
		return 1;
	}

	size_t len = gcry_sexp_sprint(keypair, GCRYSEXP_FMT_CANON, NULL, 0);
	if (len == 0) {
		fprintf(stderr, "gcry_sexp_sprint (size) failed\n");
		return 1;
	}
	unsigned char *buf = malloc(len);
	if (!buf)
		return 1;
	size_t written = gcry_sexp_sprint(keypair, GCRYSEXP_FMT_CANON, buf, len);
	if (written == 0) {
		fprintf(stderr, "gcry_sexp_sprint (write) failed\n");
		return 1;
	}

	FILE *f = fopen(argv[1], "wb");
	if (!f) {
		perror("fopen");
		return 1;
	}
	if (fwrite(buf, 1, written, f) != written) {
		fprintf(stderr, "short write\n");
		return 1;
	}
	fclose(f);
	free(buf);
	gcry_sexp_release(keypair);
	gcry_sexp_release(params);
	return 0;
}
EOF

CFLAGS=$(libgcrypt-config --cflags 2>/dev/null || true)
LIBS=$(libgcrypt-config --libs 2>/dev/null || echo -lgcrypt)
cc -O2 -o "$TMPDIR/genkey" "$TMPDIR/genkey.c" $CFLAGS $LIBS

mkdir -p "$(dirname "$OUTFILE")"
"$TMPDIR/genkey" "$OUTFILE"

echo "Fixture key written to $OUTFILE ($(wc -c < "$OUTFILE") bytes)"
