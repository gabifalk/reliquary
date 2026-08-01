/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "keyfile.h"
#include "crypto.h"
#include "secmem.h"
#include <stdio.h>
#include <stdlib.h>

#define SEAL_HEADER_LEN CRYPTO_GCM_NONCE_LEN
#define SEAL_FOOTER_LEN CRYPTO_GCM_TAG_LEN

int
keyfile_seal(const char *path, const unsigned char *key,
	     const unsigned char *plaintext, size_t pt_len)
{
	unsigned char nonce[CRYPTO_GCM_NONCE_LEN];
	unsigned char tag[CRYPTO_GCM_TAG_LEN];
	unsigned char *ct = NULL;
	FILE *f = NULL;
	int rc = -1;

	if (crypto_random(nonce, sizeof(nonce)) != 0)
		goto done;
	ct = malloc(pt_len);
	if (!ct)
		goto done;
	if (crypto_aead_encrypt(key, nonce, plaintext, pt_len, ct, tag) != 0)
		goto done;

	f = fopen(path, "wb");
	if (!f)
		goto done;
	if (fwrite(nonce, 1, sizeof(nonce), f) != sizeof(nonce))
		goto done;
	if (fwrite(ct, 1, pt_len, f) != pt_len)
		goto done;
	if (fwrite(tag, 1, sizeof(tag), f) != sizeof(tag))
		goto done;
	rc = 0;
 done:
	if (f)
		fclose(f);
	free(ct);
	return rc;
}

int
keyfile_open(const char *path, const unsigned char *key,
	     unsigned char **out, size_t * out_len)
{
	unsigned char nonce[CRYPTO_GCM_NONCE_LEN];
	unsigned char tag[CRYPTO_GCM_TAG_LEN];
	unsigned char *ct = NULL, *pt = NULL;
	FILE *f = NULL;
	int rc = -1;

	*out = NULL;
	*out_len = 0;
	f = fopen(path, "rb");
	if (!f)
		return -1;
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (fsize < (long)(SEAL_HEADER_LEN + SEAL_FOOTER_LEN))
		goto done;
	size_t ct_len = (size_t)fsize - SEAL_HEADER_LEN - SEAL_FOOTER_LEN;

	if (fread(nonce, 1, sizeof(nonce), f) != sizeof(nonce))
		goto done;
	ct = malloc(ct_len);
	if (!ct)
		goto done;
	if (fread(ct, 1, ct_len, f) != ct_len)
		goto done;
	if (fread(tag, 1, sizeof(tag), f) != sizeof(tag))
		goto done;

	pt = secure_alloc(ct_len);
	if (!pt)
		goto done;
	if (crypto_aead_decrypt(key, nonce, ct, ct_len, tag, pt) != 0) {
		secure_free(pt, ct_len);
		pt = NULL;
		goto done;
	}
	*out = pt;
	*out_len = ct_len;
	rc = 0;
 done:
	if (f)
		fclose(f);
	free(ct);
	return rc;
}
