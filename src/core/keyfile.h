/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef RELIQUARY_KEYFILE_H
# define RELIQUARY_KEYFILE_H

# include <stddef.h>

/*
 * Seal/open a key file under a raw 32-byte key (no KDF).
 * Format: nonce(12) || ciphertext(N) || tag(16).
 * keyfile_open's *out is secure_alloc'd; free via secure_free.
 */
int keyfile_seal(const char *path, const unsigned char *key,
		 const unsigned char *plaintext, size_t pt_len);
int keyfile_open(const char *path, const unsigned char *key,
		 unsigned char **out, size_t * out_len);

#endif
