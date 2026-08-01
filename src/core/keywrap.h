/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef RELIQUARY_KEYWRAP_H
# define RELIQUARY_KEYWRAP_H

# include <stddef.h>

# define KEYWRAP_MK_LEN 32

/* Mint a random master key and write <token_dir>/keywrap wrapped under PIN. */
int keywrap_create(const char *token_dir, const char *pin, size_t pin_len);

/*
 * Unwrap the master key. mk_out must be KEYWRAP_MK_LEN bytes.
 * Returns 0 on success, -1 on wrong PIN (tag mismatch), -3 on I/O error.
 */
int keywrap_open(const char *token_dir, const char *pin, size_t pin_len,
		 unsigned char *mk_out);

/* Re-wrap an existing master key under a new PIN (keeps MK, new salt/nonce). */
int keywrap_rewrap(const char *token_dir, const unsigned char *mk,
		   const char *new_pin, size_t new_len);

#endif
