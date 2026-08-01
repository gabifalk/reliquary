/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef RELIQUARY_CRYPTO_H
# define RELIQUARY_CRYPTO_H

# include <stddef.h>

int crypto_init(void);

int crypto_random(unsigned char *buf, size_t len);

#endif
