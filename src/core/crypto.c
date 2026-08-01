/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "crypto.h"
#include <gcrypt.h>

#define GCRYPT_MIN_VERSION "1.10.0"

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
