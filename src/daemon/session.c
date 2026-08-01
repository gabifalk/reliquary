/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "session.h"
#include "tokenstore.h"
#include "pin.h"
#include "meta.h"
#include "secmem.h"
#include "keywrap.h"
#include "keyfile.h"
#include <string.h>
#include <stdio.h>

/*
 * Login unwraps the PIN-wrapped master key via pin_unwrap_mk (from pin.h),
 * which centralizes the lockout check and retry-counter accounting shared
 * with CHECKPIN and WRITEKEY.
 */

void
session_init(session_t * sess, uid_t uid, const char *store_path)
{
	memset(sess, 0, sizeof(*sess));
	sess->uid = uid;
	strncpy(sess->store_path, store_path, sizeof(sess->store_path) - 1);
}

int
session_open(session_t * sess, const char *label)
{
	if (!tokenstore_exists(sess->store_path, label))
		return -1;
	session_close(sess);
	strncpy(sess->token_label, label, sizeof(sess->token_label) - 1);
	tokenstore_token_path(sess->store_path, label,
			      sess->token_dir, sizeof(sess->token_dir));
	return 0;
}

int
session_login(session_t * sess, const char *pin, size_t pin_len)
{
	if (sess->token_label[0] == '\0')
		return -3;
	session_logout(sess);

	unsigned char *mk = secure_alloc(KEYWRAP_MK_LEN);
	if (!mk)
		return -3;
	/*
	 * Throttled unwrap: pin_unwrap_mk owns the lockout check and the retry
	 * counter (decrement on wrong PIN, reset on success).
	 */
	int rc = pin_unwrap_mk(sess->token_dir, pin, pin_len, mk);
	if (rc != 0) {
		secure_free(mk, KEYWRAP_MK_LEN);
		return rc;
	}

	/* success: open each populated slot under MK */
	{
		token_meta_t m = { 0 };
		char mpath[768];
		snprintf(mpath, sizeof(mpath), "%s/metadata", sess->token_dir);
		if (meta_read(mpath, &m) == 0) {
			static const char *names[] = {
				"sign.key.enc", "encrypt.key.enc", "auth.key.enc"
			};
			for (int i = 0; i < RELIQUARY_NUM_SLOTS; i++) {
				if (!m.algorithm[i] || !m.algorithm[i][0])
					continue;
				char kpath[768];
				snprintf(kpath, sizeof(kpath), "%s/%s",
					 sess->token_dir, names[i]);
				if (keyfile_open(kpath, mk, &sess->key[i],
						 &sess->key_len[i]) == 0)
					strncpy(sess->algorithm[i], m.algorithm[i],
						sizeof(sess->algorithm[i]) - 1);
			}
			meta_free(&m);
		}
	}

	sess->mk = mk;
	sess->logged_in = 1;
	return 0;
}

void
session_logout(session_t * sess)
{
	for (int i = 0; i < RELIQUARY_NUM_SLOTS; i++) {
		if (sess->key[i]) {
			secure_free(sess->key[i], sess->key_len[i]);
			sess->key[i] = NULL;
			sess->key_len[i] = 0;
		}
		memset(sess->algorithm[i], 0, sizeof(sess->algorithm[i]));
	}
	if (sess->mk) {
		secure_free(sess->mk, KEYWRAP_MK_LEN);
		sess->mk = NULL;
	}
	sess->logged_in = 0;
}

void
session_close(session_t * sess)
{
	session_logout(sess);
	memset(sess->token_label, 0, sizeof(sess->token_label));
	memset(sess->token_dir, 0, sizeof(sess->token_dir));
}

void
session_destroy(session_t * sess)
{
	session_close(sess);
	memset(sess, 0, sizeof(*sess));
}
