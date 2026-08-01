/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef RELIQUARY_CRYPTO_RSA_H
# define RELIQUARY_CRYPTO_RSA_H

# include <stddef.h>

/* *key holds the private keypair and is secure_alloc'd; free via secure_free. */
int crypto_rsa_keygen(unsigned int nbits,
		      unsigned char **key, size_t * key_len);

int crypto_rsa_extract_pubkey(const unsigned char *key, size_t key_len,
			      unsigned char **pubkey, size_t * pubkey_len);

/* Raw RSA sign: input is pre-formatted (e.g. DigestInfo for PKCS#1 v1.5) */
int crypto_rsa_sign_raw(const unsigned char *key, size_t key_len,
			const unsigned char *data, size_t data_len,
			unsigned char **sig, size_t * sig_len);

/* PKCS#1 v1.5 */
int crypto_rsa_sign_pkcs1(const unsigned char *key, size_t key_len,
			  int hash_algo,
			  const unsigned char *hash, size_t hash_len,
			  unsigned char **sig, size_t * sig_len);

int crypto_rsa_verify_pkcs1(const unsigned char *pubkey, size_t pubkey_len,
			    int hash_algo,
			    const unsigned char *hash, size_t hash_len,
			    const unsigned char *sig, size_t sig_len);

/* PSS */
int crypto_rsa_sign_pss(const unsigned char *key, size_t key_len,
			int hash_algo,
			const unsigned char *hash, size_t hash_len,
			size_t salt_len, unsigned char **sig, size_t * sig_len);

int crypto_rsa_verify_pss(const unsigned char *pubkey, size_t pubkey_len,
			  int hash_algo,
			  const unsigned char *hash, size_t hash_len,
			  size_t salt_len,
			  const unsigned char *sig, size_t sig_len);

/*
 * PKCS#1 v1.5 encrypt/decrypt.  The decrypt *pt output is recovered secret
 * plaintext: it is secure_alloc'd and must be freed via secure_free.
 */
int crypto_rsa_encrypt_pkcs1(const unsigned char *pubkey, size_t pubkey_len,
			     const unsigned char *pt, size_t pt_len,
			     unsigned char **ct, size_t * ct_len);

int crypto_rsa_decrypt_pkcs1(const unsigned char *key, size_t key_len,
			     const unsigned char *ct, size_t ct_len,
			     unsigned char **pt, size_t * pt_len);

/*
 * OAEP encrypt/decrypt.  As with PKCS#1, the decrypt *pt output is
 * secure_alloc'd secret plaintext and must be freed via secure_free.
 */
int crypto_rsa_encrypt_oaep(const unsigned char *pubkey, size_t pubkey_len,
			    int hash_algo,
			    const unsigned char *pt, size_t pt_len,
			    unsigned char **ct, size_t * ct_len);

int crypto_rsa_decrypt_oaep(const unsigned char *key, size_t key_len,
			    int hash_algo,
			    const unsigned char *ct, size_t ct_len,
			    unsigned char **pt, size_t * pt_len);

#endif
