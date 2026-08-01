/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RELIQUARY_BUNDLED_CRYPTO_API_H
#define RELIQUARY_BUNDLED_CRYPTO_API_H
#define crypto_hash_sha512_BYTES 64U
/* SHA-512 backing for vendored bcrypt_pbkdf; implemented via libgcrypt. */
int crypto_hash_sha512(unsigned char *out, const unsigned char *in,
		       unsigned long long inlen);
#endif
