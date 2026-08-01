/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef RELIQUARY_CRYPTO_OP_H
# define RELIQUARY_CRYPTO_OP_H

# include <stddef.h>
# include <gpg-error.h>
# include "session.h"

/*
 * Shared crypto dispatch used by the neutral SIGN/DECRYPT/DERIVE commands
 * in cmd_session.c.  Raw bytes in, raw bytes out.  mech is a dotted mechanism
 * token string (e.g. "sign.rsa-pkcs1").
 *
 * Ownership of *out depends on the operation: op_sign yields public output
 * freed via free(); op_decrypt (recovered plaintext) and op_derive (ECDH
 * shared secret) yield secret material in locked memory that MUST be freed via
 * secure_free(*out, *out_len).
 *
 * These enforce the addressed slot's per-slot mechanism policy (a mechanism
 * not in the slot's allowed set is rejected) but do NOT check
 * sess->logged_in -- callers ensure the session is logged in before invoking
 * these.  Returns 0 on success, or a gpg_error_t on failure.
 */

gpg_error_t op_sign(session_t *sess, int slot, const char *mech,
		    const unsigned char *in, size_t in_len,
		    unsigned char **out, size_t *out_len);

gpg_error_t op_decrypt(session_t *sess, int slot, const char *mech,
		       const unsigned char *in, size_t in_len,
		       unsigned char **out, size_t *out_len);

gpg_error_t op_derive(session_t *sess, int slot, const char *mech,
		      const unsigned char *in, size_t in_len,
		      unsigned char **out, size_t *out_len);

/*
 * Default comma-separated dotted allowed-mechanism list for a given
 * (algorithm, slot-role) pair, used when a token's metadata has no
 * explicit allowed_mechs override for that slot.  Returns a pointer to a
 * static string -- the caller must NOT free it.  Returns "" for
 * unsupported (algorithm, slot) combinations (e.g. Ed25519 in the
 * encrypt slot).  slot is one of RELIQUARY_SLOT_SIGN/ENCRYPT/AUTH.
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
