/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "serial.h"
#include <stdio.h>

void
reliquary_format_serial(int serial_num, char *out, size_t out_len)
{
	/*
	 * OpenPGP AID: RID(5) app(1) version(2) manufacturer(2) serial(4)
	 * RFU(2).  serial_num fills the 4-byte serial-number field (bytes
	 * 10..13), which is what gpg surfaces as the card "Serial number";
	 * the trailing 0000 is the RFU.  (It must NOT sit in the RFU, or
	 * every serial_num < 65536 reads back as 00000000 and tokens are
	 * indistinguishable in gpg --card-status.)
	 */
	snprintf(out, out_len, "D276000124010300FFFF%08X0000",
		 (unsigned)serial_num);
}
