/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "crypto_api.h"
#include <gcrypt.h>
int
crypto_hash_sha512(unsigned char *out, const unsigned char *in,
		   unsigned long long inlen)
{
	gcry_md_hash_buffer(GCRY_MD_SHA512, out, in, (size_t)inlen);
	return 0;
}
