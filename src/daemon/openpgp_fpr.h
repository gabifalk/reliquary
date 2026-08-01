/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RELIQUARY_OPENPGP_FPR_H
# define RELIQUARY_OPENPGP_FPR_H

# include <stddef.h>
# include <stdint.h>

/*
 * Compute the OpenPGP v4 key fingerprint (RFC 4880 sec. 12.2 / RFC 6637): the
 * SHA-1 of 0x99 || len16 || the v4 public-key packet body
 *   0x04 || created(4) || algo || algorithm-specific public fields.
 *
 * pubkey_canon is a canonical "(public-key (rsa ...))" or "(public-key (ecc
 * (curve ..)(q ..)))" S-expression.  algo is reliquary's per-slot algorithm
 * string ("rsa2048"/"rsa3072"/"rsa4096"/"nistp256"/"nistp384"/"nistp521"/
 * "ed25519").  slot is the OpenPGP slot (0 sign, 1 encrypt, 2 auth); it selects
 * ECDH (encrypt) vs ECDSA (sign/auth) for the NIST curves.  created is the key
 * creation time in Unix seconds.
 *
 * Writes an uppercase 40-char NUL-terminated hex string to out_hex (out_sz must
 * be >= 41).  Returns 0 on success, -1 on unsupported algorithm or error.
 *
 * ECDH slots assume gpg's default KDF parameters for the curve; a key generated
 * with non-default KDF parameters would fingerprint differently (uncommon).
 */
int openpgp_v4_fpr(const char *algo, int slot, uint32_t created,
		   const unsigned char *pubkey_canon, size_t pubkey_len,
		   char *out_hex, size_t out_sz);

#endif
