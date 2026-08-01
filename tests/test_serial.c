/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "testutil.h"
#include "serial.h"
#include <string.h>

/*
 * reliquary_format_serial() emits a 16-byte OpenPGP card AID as 32 hex chars:
 *
 *   D2 76 00 01 24   01   03 00   FF FF   SS SS SS SS   00 00
 *   |__ RID (5) __|  app  ver3.0  mfr     serial(4)     RFU(2)
 *
 * The 4-byte serial-number field is bytes 10..13 -> hex chars 20..27. gpg
 * reads its human-visible "Serial number" from exactly that field, so the
 * per-token serial MUST land there (not in the RFU trailer) or every token
 * with serial_num < 65536 shows up as 00000000 and tokens are
 * indistinguishable in `gpg --card-status`.
 */

#define AID_LEN 32
#define SERIAL_FIELD_OFF 20	/* hex offset of the 4-byte serial field */

TEST(test_serial_field_holds_serial_num)
{
	char buf[64];

	reliquary_format_serial(1, buf, sizeof(buf));
	ASSERT_EQ(strlen(buf), (size_t)AID_LEN);
	/* fixed prefix: RID + app + version + manufacturer (FFFF) */
	ASSERT(strncmp(buf, "D276000124010300FFFF", SERIAL_FIELD_OFF) == 0);
	/* serial field carries serial_num */
	ASSERT(strncmp(buf + SERIAL_FIELD_OFF, "00000001", 8) == 0);
	/* RFU trailer is zero */
	ASSERT_STR_EQ(buf + 28, "0000");

	reliquary_format_serial(2, buf, sizeof(buf));
	ASSERT(strncmp(buf + SERIAL_FIELD_OFF, "00000002", 8) == 0);
	ASSERT_STR_EQ(buf + 28, "0000");

	/* full 32-bit value, uppercase hex */
	reliquary_format_serial(0x1234ABCD, buf, sizeof(buf));
	ASSERT(strncmp(buf + SERIAL_FIELD_OFF, "1234ABCD", 8) == 0);
}

TEST(test_serial_distinct_per_token)
{
	char a[64], b[64];
	reliquary_format_serial(1, a, sizeof(a));
	reliquary_format_serial(2, b, sizeof(b));
	ASSERT(strcmp(a, b) != 0);
	/* they differ specifically in the gpg-visible serial field */
	ASSERT(strncmp(a + SERIAL_FIELD_OFF, b + SERIAL_FIELD_OFF, 8) != 0);
}

TEST_MAIN_BEGIN("test_serial")
	RUN(test_serial_field_holds_serial_num);
	RUN(test_serial_distinct_per_token);
TEST_MAIN_END
