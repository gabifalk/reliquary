/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Minimal compatibility shim so the vendored OpenBSD blowfish/bcrypt_pbkdf
 * build against glibc. Included (as "includes.h") by blf.h/blowfish.c/
 * bcrypt_pbkdf.c. */
#ifndef RELIQUARY_BUNDLED_INCLUDES_H
#define RELIQUARY_BUNDLED_INCLUDES_H
#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
/* OpenBSD freezero(): zero then free. glibc lacks it; explicit_bzero is
 * exposed under _DEFAULT_SOURCE (set via the bundled lib's c_args). */
static inline void __attribute__((unused))
freezero(void *ptr, size_t len)
{
	if (ptr) {
		explicit_bzero(ptr, len);
		free(ptr);
	}
}
#endif
