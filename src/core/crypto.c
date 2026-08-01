/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "crypto.h"
#include <gcrypt.h>

#define GCRYPT_MIN_VERSION "1.10.0"
#define KDF_T_COST   3
#define KDF_M_COST   65536
#define KDF_PARALLEL 1

int
crypto_init(void)
{
	if (!gcry_check_version(GCRYPT_MIN_VERSION))
		return -1;

	gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
	gcry_control(GCRYCTL_INIT_SECMEM, 65536, 0);
	gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	return 0;
}

int
crypto_random(unsigned char *buf, size_t len)
{
	gcry_randomize(buf, len, GCRY_STRONG_RANDOM);
	return 0;
}

int
crypto_kdf_derive(const char *pin, size_t pin_len,
		  const unsigned char *salt,
		  unsigned char *key_out, size_t key_len)
{
	gcry_error_t err;
	gcry_kdf_hd_t hd;

	unsigned long param[4] = {
		(unsigned long)key_len,
		KDF_T_COST,
		KDF_M_COST,
		KDF_PARALLEL
	};

	err = gcry_kdf_open(&hd, GCRY_KDF_ARGON2, GCRY_KDF_ARGON2ID,
			    param, 4,
			    pin, pin_len,
			    salt, CRYPTO_KDF_SALT_LEN, NULL, 0, NULL, 0);
	if (err)
		return -1;

	err = gcry_kdf_compute(hd, NULL);
	if (err) {
		gcry_kdf_close(hd);
		return -1;
	}

	err = gcry_kdf_final(hd, key_len, key_out);
	gcry_kdf_close(hd);
	return err ? -1 : 0;
}

int
crypto_aead_encrypt(const unsigned char *key,
		    const unsigned char *nonce,
		    const unsigned char *plaintext, size_t pt_len,
		    unsigned char *ct_out, unsigned char *tag_out)
{
	gcry_error_t err;
	gcry_cipher_hd_t hd;

	err =
	    gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, 0);
	if (err)
		return -1;

	err = gcry_cipher_setkey(hd, key, CRYPTO_GCM_KEY_LEN);
	if (err)
		goto fail;

	err = gcry_cipher_setiv(hd, nonce, CRYPTO_GCM_NONCE_LEN);
	if (err)
		goto fail;

	err = gcry_cipher_encrypt(hd, ct_out, pt_len, plaintext, pt_len);
	if (err)
		goto fail;

	err = gcry_cipher_gettag(hd, tag_out, CRYPTO_GCM_TAG_LEN);
	if (err)
		goto fail;

	gcry_cipher_close(hd);
	return 0;

 fail:
	gcry_cipher_close(hd);
	return -1;
}

int
crypto_aead_decrypt(const unsigned char *key,
		    const unsigned char *nonce,
		    const unsigned char *ciphertext, size_t ct_len,
		    const unsigned char *tag, unsigned char *pt_out)
{
	gcry_error_t err;
	gcry_cipher_hd_t hd;

	err =
	    gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, 0);
	if (err)
		return -1;

	err = gcry_cipher_setkey(hd, key, CRYPTO_GCM_KEY_LEN);
	if (err)
		goto fail;

	err = gcry_cipher_setiv(hd, nonce, CRYPTO_GCM_NONCE_LEN);
	if (err)
		goto fail;

	err = gcry_cipher_decrypt(hd, pt_out, ct_len, ciphertext, ct_len);
	if (err)
		goto fail;

	err = gcry_cipher_checktag(hd, tag, CRYPTO_GCM_TAG_LEN);
	if (err)
		goto fail;

	gcry_cipher_close(hd);
	return 0;

 fail:
	gcry_cipher_close(hd);
	return -1;
}
