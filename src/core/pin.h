/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef RELIQUARY_PIN_H
# define RELIQUARY_PIN_H

# include <stdbool.h>
# include <stddef.h>

/*
 * Compute PIN salt and hash for storage in metadata.
 * Caller must free *salt_hex_out and *hash_hex_out.
 */
int pin_create_hash(const char *pin, size_t pin_len,
		    char **salt_hex_out, char **hash_hex_out);

bool pin_is_locked(const char *token_dir);

/*
 * Throttled unwrap of a token's master key with the token PIN. This is the
 * single choke point for token-PIN attempts: it enforces the lockout and the
 * retry counter so that every PIN-guessing path (LOGIN, CHECKPIN, WRITEKEY)
 * is throttled identically.
 *
 * mk_out must be KEYWRAP_MK_LEN bytes. Returns:
 *   0  success (master key written to mk_out; retry counter reset to max)
 *  -1  wrong PIN (retry counter decremented, floored at 0)
 *  -2  locked (retry counter already exhausted; keywrap not even attempted)
 *  -3  I/O error (retry counter left untouched)
 */
int pin_unwrap_mk(const char *token_dir, const char *pin, size_t pin_len,
		  unsigned char *mk_out);

#endif
