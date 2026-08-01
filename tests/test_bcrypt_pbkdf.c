/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "testutil.h"
#include "bcrypt_pbkdf.h"
#include <gcrypt.h>
#include <string.h>

/* rounds=4, "password"/"salt" -> 32 bytes (OpenBSD regress vector 1) */
TEST(test_bcrypt_pbkdf_v1)
{
	uint8_t out[32];
	static const uint8_t want[] =
	    "\x5b\xbf\x0c\xc2\x93\x58\x7f\x1c\x36\x35\x55\x5c\x27\x79\x65\x98"
	    "\xd4\x7e\x57\x90\x71\xbf\x42\x7e\x9d\x8f\xbe\x84\x2a\xba\x34\xd9";
	ASSERT_EQ(bcrypt_pbkdf("password", 8, (const uint8_t *)"salt", 4,
			       out, sizeof(out), 4), 0);
	ASSERT_MEM_EQ(out, want, 32);
}

/* rounds=8, "password"/"salt" -> 64 bytes (OpenBSD regress "bigger key") */
TEST(test_bcrypt_pbkdf_v2)
{
	uint8_t out[64];
	static const uint8_t want[] =
	    "\xe1\x36\x7e\xc5\x15\x1a\x33\xfa\xac\x4c\xc1\xc1\x44\xcd\x23\xfa"
	    "\x15\xd5\x54\x84\x93\xec\xc9\x9b\x9b\x5d\x9c\x0d\x3b\x27\xbe\xc7"
	    "\x62\x27\xea\x66\x08\x8b\x84\x9b\x20\xab\x7a\xa4\x78\x01\x02\x46"
	    "\xe7\x4b\xba\x51\x72\x3f\xef\xa9\xf9\x47\x4d\x65\x08\x84\x5e\x8d";
	ASSERT_EQ(bcrypt_pbkdf("password", 8, (const uint8_t *)"salt", 4,
			       out, sizeof(out), 8), 0);
	ASSERT_MEM_EQ(out, want, 64);
}

TEST_MAIN_BEGIN("test_bcrypt_pbkdf")
	ASSERT(gcry_check_version(NULL));
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	RUN(test_bcrypt_pbkdf_v1);
	RUN(test_bcrypt_pbkdf_v2);
TEST_MAIN_END
