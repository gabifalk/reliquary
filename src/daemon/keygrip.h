/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef RELIQUARY_KEYGRIP_H
# define RELIQUARY_KEYGRIP_H
# include <stddef.h>

/*
 * Compute the GnuPG keygrip (SHA-1 of libgcrypt's canonical public-key
 * S-expression) of the hex-encoded public-key S-expression pubkey_hex.
 * Writes an uppercase 40-char NUL-terminated hex string to grip_out
 * (grip_size must be >= 41).  Returns 0 on success, -1 on failure.
 */
int compute_keygrip(const char *pubkey_hex, char *grip_out, size_t grip_size);

/*
 * Return 0 if a keygrip can be computed for the canonical public-key
 * S-expression pubkey_canon, -1 otherwise -- crucially without aborting the
 * caller. gcry_pk_get_keygrip() calls log_fatal()->abort() on some malformed
 * public keys, so the computation runs in a forked child; a child killed by a
 * signal (or exiting nonzero) means "not computable". Use this to reject
 * un-keygrippable keys at import time, so the read path (compute_keygrip) only
 * ever runs on validated keys.
 */
int keygrip_computable(const unsigned char *pubkey_canon, size_t len);

#endif
