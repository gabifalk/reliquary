/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef RELIQUARY_CRYPTO_EC_H
# define RELIQUARY_CRYPTO_EC_H

# include <stddef.h>

/* *key holds the private keypair and is secure_alloc'd; free via secure_free. */
int crypto_ec_keygen(const char *curve, unsigned char **key, size_t * key_len);

int crypto_ec_extract_pubkey(const unsigned char *key, size_t key_len,
			     unsigned char **pubkey, size_t * pubkey_len);

/* ECDSA sign -- returns serialized signature (implementation-defined format). */
int crypto_ecdsa_sign(const unsigned char *key, size_t key_len,
		      const unsigned char *hash, size_t hash_len,
		      unsigned char **sig, size_t * sig_len);

/*
 * ECDSA/EdDSA sign -- returns the raw signature as fixed-width r||s (each half
 * padded to the larger component size).  This is the form both the PKCS#11
 * module's CKM_ECDSA mechanism and gpg-agent's smartcard sign path expect;
 * the daemon's sign.ecdsa/sign.eddsa wire mechanisms use this function to
 * produce it.
 */
int crypto_ecdsa_sign_raw(const unsigned char *key, size_t key_len,
			  const unsigned char *hash, size_t hash_len,
			  unsigned char **sig, size_t * sig_len);

int crypto_ecdsa_verify(const unsigned char *pubkey, size_t pubkey_len,
			const unsigned char *hash, size_t hash_len,
			const unsigned char *sig, size_t sig_len);

/*
 * ECDH key agreement. Returns the raw shared secret in *secret; it is
 * secure_alloc'd secret material and must be freed via secure_free.
 */
int crypto_ecdh_derive(const unsigned char *key, size_t key_len,
		       const unsigned char *peer_pubkey, size_t peer_pubkey_len,
		       unsigned char **secret, size_t * secret_len);

#endif
