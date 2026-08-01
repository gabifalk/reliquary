/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "keywrap.h"
#include "crypto.h"
#include "secmem.h"
#include <stdio.h>
#include <string.h>

/* file: salt(16) || nonce(12) || wrapped_mk(32) || tag(16) */
#define KW_LEN (CRYPTO_KDF_SALT_LEN + CRYPTO_GCM_NONCE_LEN \
		+ KEYWRAP_MK_LEN + CRYPTO_GCM_TAG_LEN)

static void
kw_path(const char *dir, char *buf, size_t n)
{
	snprintf(buf, n, "%s/keywrap", dir);
}

static int
kw_write(const char *dir, const unsigned char *salt,
	 const unsigned char *nonce, const unsigned char *wrapped,
	 const unsigned char *tag)
{
	char path[512];
	kw_path(dir, path, sizeof(path));
	FILE *f = fopen(path, "wb");
	if (!f)
		return -3;
	int ok = fwrite(salt, 1, CRYPTO_KDF_SALT_LEN, f) == CRYPTO_KDF_SALT_LEN
	    && fwrite(nonce, 1, CRYPTO_GCM_NONCE_LEN, f) == CRYPTO_GCM_NONCE_LEN
	    && fwrite(wrapped, 1, KEYWRAP_MK_LEN, f) == KEYWRAP_MK_LEN
	    && fwrite(tag, 1, CRYPTO_GCM_TAG_LEN, f) == CRYPTO_GCM_TAG_LEN;
	fclose(f);
	return ok ? 0 : -3;
}

static int
wrap_and_write(const char *dir, const unsigned char *mk,
	       const char *pin, size_t pin_len)
{
	unsigned char salt[CRYPTO_KDF_SALT_LEN];
	unsigned char nonce[CRYPTO_GCM_NONCE_LEN];
	unsigned char kek[CRYPTO_GCM_KEY_LEN];
	unsigned char wrapped[KEYWRAP_MK_LEN];
	unsigned char tag[CRYPTO_GCM_TAG_LEN];
	int rc = -3;

	if (crypto_random(salt, sizeof(salt)) != 0)
		goto done;
	if (crypto_random(nonce, sizeof(nonce)) != 0)
		goto done;
	if (crypto_kdf_derive(pin, pin_len, salt, kek, sizeof(kek)) != 0)
		goto done;
	if (crypto_aead_encrypt(kek, nonce, mk, KEYWRAP_MK_LEN, wrapped, tag)
	    != 0)
		goto done;
	rc = kw_write(dir, salt, nonce, wrapped, tag);
 done:
	secure_zero(kek, sizeof(kek));
	return rc;
}

int
keywrap_create(const char *token_dir, const char *pin, size_t pin_len)
{
	unsigned char mk[KEYWRAP_MK_LEN];
	int rc = -3;
	if (crypto_random(mk, sizeof(mk)) != 0)
		goto done;
	rc = wrap_and_write(token_dir, mk, pin, pin_len);
 done:
	secure_zero(mk, sizeof(mk));
	return rc;
}

int
keywrap_rewrap(const char *token_dir, const unsigned char *mk,
	       const char *new_pin, size_t new_len)
{
	return wrap_and_write(token_dir, mk, new_pin, new_len);
}

int
keywrap_open(const char *token_dir, const char *pin, size_t pin_len,
	     unsigned char *mk_out)
{
	char path[512];
	kw_path(token_dir, path, sizeof(path));
	FILE *f = fopen(path, "rb");
	if (!f)
		return -3;

	unsigned char buf[KW_LEN];
	size_t n = fread(buf, 1, sizeof(buf), f);
	fclose(f);
	if (n != KW_LEN)
		return -3;

	const unsigned char *salt = buf;
	const unsigned char *nonce = salt + CRYPTO_KDF_SALT_LEN;
	const unsigned char *wrapped = nonce + CRYPTO_GCM_NONCE_LEN;
	const unsigned char *tag = wrapped + KEYWRAP_MK_LEN;

	unsigned char kek[CRYPTO_GCM_KEY_LEN];
	int rc = -3;
	if (crypto_kdf_derive(pin, pin_len, salt, kek, sizeof(kek)) != 0)
		goto done;
	if (crypto_aead_decrypt(kek, nonce, wrapped, KEYWRAP_MK_LEN, tag,
				mk_out) != 0) {
		rc = -1;		/* wrong PIN */
		goto done;
	}
	rc = 0;
 done:
	secure_zero(kek, sizeof(kek));
	return rc;
}
