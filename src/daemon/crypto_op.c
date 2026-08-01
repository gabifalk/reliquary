/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "crypto_op.h"
#include "meta.h"
#include "crypto_rsa.h"
#include "crypto_ec.h"
#include "secmem.h"
#include <gcrypt.h>
#include <gpg-error.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum mech_op { MECH_OP_SIGN, MECH_OP_DECRYPT, MECH_OP_DERIVE };

struct mech_entry {
	const char *token;
	enum mech_op op;
	int advertised;
};

/*
 * The one authoritative mechanism table.  Every other view -- op_* dispatch,
 * mechpolicy_default_set, GET_MECHANISM_LIST -- derives from this.
 */
static const struct mech_entry MECH_TABLE[] = {
	{ "sign.rsa-pkcs1",    MECH_OP_SIGN,    1 },
	{ "sign.rsa-pss",      MECH_OP_SIGN,    1 },
	{ "sign.ecdsa",        MECH_OP_SIGN,    1 },
	{ "sign.eddsa",        MECH_OP_SIGN,    1 },
	{ "decrypt.rsa-pkcs1", MECH_OP_DECRYPT, 1 },
	{ "decrypt.rsa-oaep",  MECH_OP_DECRYPT, 1 },
	{ "decrypt.rsa-raw",   MECH_OP_DECRYPT, 0 },
	{ "derive.ecdh",       MECH_OP_DERIVE,  1 },
};
#define MECH_TABLE_LEN (sizeof(MECH_TABLE) / sizeof(MECH_TABLE[0]))

void
mechpolicy_advertised(char *buf, size_t buflen)
{
	size_t off = 0;
	if (buflen == 0)
		return;
	buf[0] = '\0';
	for (size_t i = 0; i < MECH_TABLE_LEN; i++) {
		if (!MECH_TABLE[i].advertised)
			continue;
		int n = snprintf(buf + off, buflen - off, "%s%s",
				 off ? "\n" : "", MECH_TABLE[i].token);
		if (n < 0 || (size_t)n >= buflen - off)
			break;
		off += (size_t)n;
	}
}

/*
 * Whole-segment membership test: does the comma-separated dotted-token list `set`
 * contain `mech` as a complete element (not a substring)?  Empty/NULL set
 * contains nothing.
 */
static int
mech_in_set(const char *set, const char *mech)
{
	if (!set || !mech)
		return 0;
	size_t mlen = strlen(mech);
	const char *p = set;
	while (*p) {
		const char *comma = strchr(p, ',');
		size_t seg = comma ? (size_t)(comma - p) : strlen(p);
		if (seg == mlen && memcmp(p, mech, mlen) == 0)
			return 1;
		if (!comma)
			break;
		p = comma + 1;
	}
	return 0;
}

/*
 * Enforce the per-slot allowed-mechanism policy before any crypto runs.
 * Reads the token metadata for this session's open token and computes the
 * slot's EFFECTIVE allowed set: the stored allowed_mechs[slot] if present and
 * non-empty, else mechpolicy_default_set() for the slot's algorithm.  The
 * default-set fallback is essential -- many existing tokens (anything written
 * before per-slot policy, and every test fixture) have allowed_mechs == NULL,
 * and rejecting those would break every existing key.  Returns 0 if `mech` is
 * a member of the effective set, else GPG_ERR_NOT_SUPPORTED.
 */
static gpg_error_t
check_mech_allowed(session_t *sess, int slot, const char *mech)
{
	token_meta_t m = { 0 };
	char mpath[768];
	snprintf(mpath, sizeof(mpath), "%s/metadata", sess->token_dir);
	if (meta_read(mpath, &m) != 0)
		return gpg_error(GPG_ERR_NOT_SUPPORTED);

	const char *effective;
	if (m.allowed_mechs[slot] && *m.allowed_mechs[slot])
		effective = m.allowed_mechs[slot];
	else
		effective = mechpolicy_default_set(m.algorithm[slot], slot);

	int allowed = mech_in_set(effective, mech);
	meta_free(&m);
	return allowed ? 0 : gpg_error(GPG_ERR_NOT_SUPPORTED);
}

gpg_error_t
op_sign(session_t *sess, int slot, const char *mech,
	const unsigned char *in, size_t in_len,
	unsigned char **out, size_t *out_len)
{
	int rc;

	gpg_error_t perr = check_mech_allowed(sess, slot, mech);
	if (perr)
		return perr;

	if (strcmp(mech, "sign.rsa-pkcs1") == 0
	    && algo_is_rsa(sess->algorithm[slot]))
		rc = crypto_rsa_sign_raw(sess->key[slot], sess->key_len[slot],
					 in, in_len, out, out_len);
	else if (strcmp(mech, "sign.rsa-pss") == 0
		 && algo_is_rsa(sess->algorithm[slot]))
		rc = crypto_rsa_sign_pss(sess->key[slot], sess->key_len[slot],
					 GCRY_MD_SHA256, in, in_len, 32,
					 out, out_len);
	else if (strcmp(mech, "sign.ecdsa") == 0
		 && algo_is_ec(sess->algorithm[slot]))
		/*
		 * The PKCS#11 module's CKM_ECDSA mechanism needs raw r||s
		 * concatenation; the daemon's sign.ecdsa wire mechanism
		 * produces that same format for that consumer.
		 */
		rc = crypto_ecdsa_sign_raw(sess->key[slot], sess->key_len[slot],
					   in, in_len, out, out_len);
	else if (strcmp(mech, "sign.eddsa") == 0
		 && algo_is_ed25519(sess->algorithm[slot]))
		/* PureEdDSA over the raw message; returns raw 64-byte r||s. */
		rc = crypto_ecdsa_sign_raw(sess->key[slot], sess->key_len[slot],
					   in, in_len, out, out_len);
	else
		return gpg_error(GPG_ERR_NOT_SUPPORTED);

	if (rc != 0)
		return gpg_error(GPG_ERR_GENERAL);
	return 0;
}

/*
 * Raw RSA decrypt (decrypt.rsa-raw): no padding is expected or stripped here --
 * the caller (the scdaemon PKDECRYPT path, via gpg-agent) handles that.
 */
static gpg_error_t
rsa_decrypt_raw(session_t *sess, int slot,
		const unsigned char *in, size_t in_len,
		unsigned char **out, size_t *out_len)
{
	gcry_sexp_t privkey = NULL, enc_sexp = NULL, plain_sexp = NULL;
	gcry_error_t gerr;

	gerr = gcry_sexp_new(&privkey, sess->key[slot], sess->key_len[slot], 0);
	if (gerr)
		return gpg_error(GPG_ERR_GENERAL);

	gerr = gcry_sexp_build(&enc_sexp, NULL,
			       "(enc-val (flags raw) (rsa (a %b)))",
			       (int)in_len, in);
	if (gerr) {
		gcry_sexp_release(privkey);
		return gpg_error(GPG_ERR_GENERAL);
	}

	gerr = gcry_pk_decrypt(&plain_sexp, enc_sexp, privkey);
	gcry_sexp_release(enc_sexp);
	gcry_sexp_release(privkey);
	if (gerr)
		return gpg_error(GPG_ERR_GENERAL);

	size_t pt_len = 0;
	const char *pt = gcry_sexp_nth_data(plain_sexp, 1, &pt_len);
	if (!pt || pt_len == 0) {
		gcry_sexp_release(plain_sexp);
		return gpg_error(GPG_ERR_GENERAL);
	}

	/*
	 * Recovered plaintext is secret -- keep it in locked memory; the
	 * caller frees *out via secure_free.
	 */
	unsigned char *buf = secure_alloc(pt_len);
	if (!buf) {
		gcry_sexp_release(plain_sexp);
		return gpg_error(GPG_ERR_ENOMEM);
	}
	memcpy(buf, pt, pt_len);
	gcry_sexp_release(plain_sexp);

	*out = buf;
	*out_len = pt_len;
	return 0;
}

gpg_error_t
op_decrypt(session_t *sess, int slot, const char *mech,
	   const unsigned char *in, size_t in_len,
	   unsigned char **out, size_t *out_len)
{
	int rc;

	gpg_error_t perr = check_mech_allowed(sess, slot, mech);
	if (perr)
		return perr;

	if (strcmp(mech, "decrypt.rsa-pkcs1") == 0
	    && algo_is_rsa(sess->algorithm[slot]))
		rc = crypto_rsa_decrypt_pkcs1(sess->key[slot], sess->key_len[slot],
					      in, in_len, out, out_len);
	else if (strcmp(mech, "decrypt.rsa-oaep") == 0
		 && algo_is_rsa(sess->algorithm[slot]))
		rc = crypto_rsa_decrypt_oaep(sess->key[slot], sess->key_len[slot],
					     GCRY_MD_SHA256, in, in_len,
					     out, out_len);
	else if (strcmp(mech, "decrypt.rsa-raw") == 0
		 && algo_is_rsa(sess->algorithm[slot]))
		return rsa_decrypt_raw(sess, slot, in, in_len, out, out_len);
	else
		return gpg_error(GPG_ERR_NOT_SUPPORTED);

	if (rc != 0)
		return gpg_error(GPG_ERR_GENERAL);
	return 0;
}

gpg_error_t
op_derive(session_t *sess, int slot, const char *mech,
	  const unsigned char *in, size_t in_len,
	  unsigned char **out, size_t *out_len)
{
	gpg_error_t perr = check_mech_allowed(sess, slot, mech);
	if (perr)
		return perr;

	if (strcmp(mech, "derive.ecdh") != 0
	    || !algo_is_ec(sess->algorithm[slot]))
		return gpg_error(GPG_ERR_NOT_SUPPORTED);

	int rc = crypto_ecdh_derive(sess->key[slot], sess->key_len[slot],
				    in, in_len, out, out_len);
	if (rc != 0)
		return gpg_error(GPG_ERR_GENERAL);
	return 0;
}

const char *
mechpolicy_default_set(const char *algo, int slot)
{
	/* Ed25519 is also algo_is_ec(), so it must be tested first. */
	if (algo_is_ed25519(algo)) {
		switch (slot) {
		case RELIQUARY_SLOT_SIGN:
			return "sign.eddsa";
		case RELIQUARY_SLOT_ENCRYPT:
			return "";
		case RELIQUARY_SLOT_AUTH:
			return "sign.eddsa";
		default:
			return "";
		}
	}

	if (algo_is_ec(algo)) {
		switch (slot) {
		case RELIQUARY_SLOT_SIGN:
			return "sign.ecdsa";
		case RELIQUARY_SLOT_ENCRYPT:
			return "derive.ecdh";
		case RELIQUARY_SLOT_AUTH:
			return "sign.ecdsa";
		default:
			return "";
		}
	}

	if (algo_is_rsa(algo)) {
		switch (slot) {
		case RELIQUARY_SLOT_SIGN:
			return "sign.rsa-pkcs1,sign.rsa-pss";
		case RELIQUARY_SLOT_ENCRYPT:
			return "decrypt.rsa-pkcs1,decrypt.rsa-oaep";
		case RELIQUARY_SLOT_AUTH:
			return "sign.rsa-pkcs1";
		default:
			return "";
		}
	}

	return "";
}
