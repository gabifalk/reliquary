/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef RELIQUARY_CRYPTO_H
# define RELIQUARY_CRYPTO_H

# include <stddef.h>

# define CRYPTO_KDF_SALT_LEN   16
# define CRYPTO_GCM_KEY_LEN    32
# define CRYPTO_GCM_NONCE_LEN  12
# define CRYPTO_GCM_TAG_LEN    16

int crypto_init(void);

int crypto_kdf_derive(const char *pin, size_t pin_len,
		      const unsigned char *salt,
		      unsigned char *key_out, size_t key_len);

int crypto_aead_encrypt(const unsigned char *key,
			const unsigned char *nonce,
			const unsigned char *plaintext, size_t pt_len,
			unsigned char *ct_out, unsigned char *tag_out);

int crypto_aead_decrypt(const unsigned char *key,
			const unsigned char *nonce,
			const unsigned char *ciphertext, size_t ct_len,
			const unsigned char *tag, unsigned char *pt_out);

int crypto_random(unsigned char *buf, size_t len);

#endif
