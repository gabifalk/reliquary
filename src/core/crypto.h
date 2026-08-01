/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef RELIQUARY_CRYPTO_H
# define RELIQUARY_CRYPTO_H

# include <stddef.h>

# define CRYPTO_KDF_SALT_LEN   16
# define CRYPTO_GCM_KEY_LEN    32

int crypto_init(void);

int crypto_kdf_derive(const char *pin, size_t pin_len,
		      const unsigned char *salt,
		      unsigned char *key_out, size_t key_len);

int crypto_random(unsigned char *buf, size_t len);

#endif
