/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef RELIQUARY_CRYPTO_OP_H
# define RELIQUARY_CRYPTO_OP_H

# include <stddef.h>
# include "session.h"

/*
 * Default comma-separated dotted-token list for a given (algorithm,
 * slot-role) pair, used when a token's metadata has no explicit
 * allowed_mechs override for that slot.  Returns a pointer to a static
 * string -- the caller must NOT free it.  Returns "" for unsupported
 * (algorithm, slot) combinations (e.g. Ed25519 in the encrypt slot).  slot
 * is one of RELIQUARY_SLOT_SIGN/ENCRYPT/AUTH.
 */
const char *mechpolicy_default_set(const char *algo, int slot);

/*
 * Write the newline-separated list of advertised mechanism tokens into buf
 * (NUL-terminated, no trailing newline).  This is the single source of truth
 * for GET_MECHANISM_LIST; it excludes accepted-but-unadvertised mechanisms
 * such as decrypt.rsa-raw.
 */
void mechpolicy_advertised(char *buf, size_t buflen);

#endif
