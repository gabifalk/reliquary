/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RELIQUARY_BUNDLED_BCRYPT_PBKDF_H
#define RELIQUARY_BUNDLED_BCRYPT_PBKDF_H
#include <stddef.h>
#include <stdint.h>
int bcrypt_pbkdf(const char *pass, size_t passlen, const uint8_t *salt,
		 size_t saltlen, uint8_t *key, size_t keylen,
		 unsigned int rounds);
#endif
