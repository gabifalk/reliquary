/* SPDX-License-Identifier: GPL-2.0-or-later */

#define _DEFAULT_SOURCE
#include "secmem.h"
#include <gcrypt.h>
#include <stdlib.h>
#include <string.h>

void
secure_zero(void *ptr, size_t len)
{
	if (!ptr)
		return;
#if defined(__GLIBC__) && __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 25
	explicit_bzero(ptr, len);
#else
	volatile unsigned char *p = ptr;
	while (len--)
		*p++ = 0;
#endif
}

void *
secure_alloc(size_t len)
{
	void *p = gcry_malloc_secure(len);
	if (p)
		memset(p, 0, len);
	return p;
}

void
secure_free(void *ptr, size_t len)
{
	if (!ptr)
		return;
	secure_zero(ptr, len);
	gcry_free(ptr);
}
