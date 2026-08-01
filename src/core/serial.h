/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef RELIQUARY_SERIAL_H
# define RELIQUARY_SERIAL_H
# include <stddef.h>

/*
 * Format a token's canonical serial number.  This is the single source
 * of truth for the serial string, shared by the neutral PKCS#11 face
 * (GET_ATTRIBUTE serial in cmd_session.c, surfaced as
 * CK_TOKEN_INFO.serialNumber by the stub in pkcs11/libreliquary.c) and
 * the scd-proxy's own SERIALNO/KEYINFO translation, so all agree on
 * token identity.
 */
void reliquary_format_serial(int serial_num, char *out, size_t out_len);

#endif
