/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "hex.h"
#include <stdlib.h>
#include <string.h>

char *
hex_encode(const unsigned char *data, size_t len)
{
	char *out = malloc(2 * len + 1);
	if (!out)
		return NULL;

	static const char tbl[] = "0123456789abcdef";
	for (size_t i = 0; i < len; i++) {
		out[2 * i] = tbl[data[i] >> 4];
		out[2 * i + 1] = tbl[data[i] & 0x0f];
	}
	out[2 * len] = '\0';
	return out;
}

static int
hex_val(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

int
hex_decode(const char *hex, unsigned char *out, size_t out_size,
	   size_t * out_len)
{
	if (!hex || !out || !out_len)
		return -1;

	size_t slen = strlen(hex);
	if (slen % 2 != 0)
		return -1;

	size_t nbytes = slen / 2;
	if (nbytes > out_size)
		return -1;

	for (size_t i = 0; i < nbytes; i++) {
		int hi = hex_val(hex[2 * i]);
		int lo = hex_val(hex[2 * i + 1]);
		if (hi < 0 || lo < 0)
			return -1;
		out[i] = (unsigned char)((hi << 4) | lo);
	}

	*out_len = nbytes;
	return 0;
}
