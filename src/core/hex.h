/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef RELIQUARY_HEX_H
# define RELIQUARY_HEX_H

# include <stddef.h>

char *hex_encode(const unsigned char *data, size_t len);

int hex_decode(const char *hex, unsigned char *out, size_t out_size,
	       size_t * out_len);

#endif
