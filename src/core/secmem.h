/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef RELIQUARY_SECMEM_H
# define RELIQUARY_SECMEM_H

# include <stddef.h>

void secure_zero(void *ptr, size_t len);
void *secure_alloc(size_t len);
void secure_free(void *ptr, size_t len);

#endif
