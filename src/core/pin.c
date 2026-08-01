/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "pin.h"
#include "meta.h"
#include "keywrap.h"
#include "crypto.h"
#include "hex.h"
#include "secmem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void
meta_path(const char *dir, char *buf, size_t buf_len)
{
	snprintf(buf, buf_len, "%s/metadata", dir);
}

bool
pin_is_locked(const char *token_dir)
{
	char mpath[512];
	meta_path(token_dir, mpath, sizeof(mpath));

	token_meta_t m = { 0 };
	if (meta_read(mpath, &m) != 0)
		return true;

	token_state_t st;
	int retries;
	if (state_read(token_dir, &st) == 0 && st.pin_retries >= 0)
		retries = st.pin_retries;
	else
		retries = m.pin_max_retries;

	meta_free(&m);
	return retries <= 0;
}

int
pin_unwrap_mk(const char *token_dir, const char *pin, size_t pin_len,
	      unsigned char *mk_out)
{
	if (pin_is_locked(token_dir))
		return -2;

	int rc = keywrap_open(token_dir, pin, pin_len, mk_out);
	if (rc == -1) {			/* wrong PIN: consume a retry */
		token_state_t st = { .pin_retries = -1, .disconnected = 0 };
		state_read(token_dir, &st);
		token_meta_t m = { 0 };
		char mpath[768];
		snprintf(mpath, sizeof(mpath), "%s/metadata", token_dir);
		int maxr = (meta_read(mpath, &m) == 0) ? m.pin_max_retries : 0;
		meta_free(&m);
		int cur = st.pin_retries >= 0 ? st.pin_retries : maxr;
		st.pin_retries = cur > 0 ? cur - 1 : 0;
		state_write(token_dir, &st);
		return -1;
	}
	if (rc != 0)			/* I/O error: leave the counter alone */
		return rc;

	/* success: reset the retry counter to the configured maximum */
	token_meta_t m = { 0 };
	char mpath[768];
	snprintf(mpath, sizeof(mpath), "%s/metadata", token_dir);
	if (meta_read(mpath, &m) == 0) {
		token_state_t st = { .pin_retries = m.pin_max_retries,
				     .disconnected = 0 };
		state_read(token_dir, &st);
		st.pin_retries = m.pin_max_retries;
		state_write(token_dir, &st);
		meta_free(&m);
	}
	return 0;
}

int
pin_create_hash(const char *pin, size_t pin_len,
		char **salt_hex_out, char **hash_hex_out)
{
	unsigned char salt[CRYPTO_KDF_SALT_LEN];
	unsigned char hash[CRYPTO_GCM_KEY_LEN];
	int rc = -1;

	if (crypto_random(salt, sizeof(salt)) != 0)
		goto out;

	/* hash is PIN-derived key material; wipe the stack copies below. */
	if (crypto_kdf_derive(pin, pin_len, salt, hash, sizeof(hash)) != 0)
		goto out;

	*salt_hex_out = hex_encode(salt, sizeof(salt));
	*hash_hex_out = hex_encode(hash, sizeof(hash));
	if (!*salt_hex_out || !*hash_hex_out) {
		free(*salt_hex_out);
		free(*hash_hex_out);
		*salt_hex_out = NULL;
		*hash_hex_out = NULL;
		goto out;
	}
	rc = 0;

 out:
	secure_zero(salt, sizeof(salt));
	secure_zero(hash, sizeof(hash));
	return rc;
}
