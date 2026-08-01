/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "crypto_op.h"
#include "meta.h"
#include <stdio.h>

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
