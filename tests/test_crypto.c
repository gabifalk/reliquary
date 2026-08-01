/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "testutil.h"
#include "crypto.h"
#include <string.h>

TEST(test_init)
{
	ASSERT_EQ(crypto_init(), 0);
}

TEST(test_random_fills_buffer)
{
	unsigned char buf[32];
	memset(buf, 0, sizeof(buf));
	ASSERT_EQ(crypto_random(buf, sizeof(buf)), 0);
	int all_zero = 1;
	for (size_t i = 0; i < sizeof(buf); i++)
		if (buf[i] != 0) {
			all_zero = 0;
			break;
		}
	ASSERT(!all_zero);
}

TEST(test_random_distinct)
{
	unsigned char a[32], b[32];
	crypto_random(a, sizeof(a));
	crypto_random(b, sizeof(b));
	ASSERT(memcmp(a, b, sizeof(a)) != 0);
}

TEST_MAIN_BEGIN("test_crypto")
    RUN(test_init);
RUN(test_random_fills_buffer);
RUN(test_random_distinct);
TEST_MAIN_END
