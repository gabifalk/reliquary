/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "testutil.h"
#include "secmem.h"
#include "crypto.h"

TEST(test_secure_zero_clears)
{
	unsigned char buf[32];
	memset(buf, 0xaa, sizeof(buf));
	secure_zero(buf, sizeof(buf));
	for (size_t i = 0; i < sizeof(buf); i++)
		ASSERT_EQ(buf[i], 0);
}

TEST(test_secure_zero_null_noop)
{
	secure_zero(NULL, 0);
	secure_zero(NULL, 10);
	/* must not crash */
}

TEST(test_secure_alloc_returns_zeroed)
{
	unsigned char *p = secure_alloc(64);
	ASSERT_NOT_NULL(p);
	for (size_t i = 0; i < 64; i++)
		ASSERT_EQ(p[i], 0);
	secure_free(p, 64);
}

TEST(test_secure_free_null_noop)
{
	secure_free(NULL, 0);
	/* must not crash */
}

TEST(test_secure_alloc_is_usable_after_init)
{
	unsigned char *p = secure_alloc(64);
	ASSERT_NOT_NULL(p);
	for (int i = 0; i < 64; i++)
		p[i] = (unsigned char)i;
	ASSERT_EQ(p[63], 63);
	secure_free(p, 64);
}

TEST_MAIN_BEGIN("test_secmem")
    ASSERT_EQ(crypto_init(), 0);
RUN(test_secure_zero_clears);
RUN(test_secure_zero_null_noop);
RUN(test_secure_alloc_returns_zeroed);
RUN(test_secure_free_null_noop);
RUN(test_secure_alloc_is_usable_after_init);
TEST_MAIN_END
