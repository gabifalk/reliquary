/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "testutil.h"
#include "keywrap.h"
#include "crypto.h"
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

static const char *dir = "/tmp/test_reliquary_keywrap";

static void
setup(void)
{
	mkdir(dir, 0700);
	char p[256];
	snprintf(p, sizeof(p), "%s/keywrap", dir);
	unlink(p);
}

TEST(test_create_open_roundtrip)
{
	setup();
	ASSERT_EQ(keywrap_create(dir, "1234", 4), 0);

	unsigned char mk1[KEYWRAP_MK_LEN], mk2[KEYWRAP_MK_LEN];
	ASSERT_EQ(keywrap_open(dir, "1234", 4, mk1), 0);
	ASSERT_EQ(keywrap_open(dir, "1234", 4, mk2), 0);
	ASSERT_MEM_EQ(mk1, mk2, KEYWRAP_MK_LEN);	/* stable */
}

TEST(test_open_wrong_pin_fails)
{
	setup();
	ASSERT_EQ(keywrap_create(dir, "right", 5), 0);
	unsigned char mk[KEYWRAP_MK_LEN];
	ASSERT_EQ(keywrap_open(dir, "wrong", 5, mk), -1);
}

TEST(test_rewrap_changes_pin)
{
	setup();
	ASSERT_EQ(keywrap_create(dir, "old", 3), 0);
	unsigned char mk[KEYWRAP_MK_LEN];
	ASSERT_EQ(keywrap_open(dir, "old", 3, mk), 0);

	ASSERT_EQ(keywrap_rewrap(dir, mk, "new", 3), 0);
	unsigned char mk2[KEYWRAP_MK_LEN];
	ASSERT_EQ(keywrap_open(dir, "old", 3, mk2), -1);	/* old rejected */
	ASSERT_EQ(keywrap_open(dir, "new", 3, mk2), 0);	/* new works */
	ASSERT_MEM_EQ(mk, mk2, KEYWRAP_MK_LEN);		/* same MK */
}

TEST_MAIN_BEGIN("test_keywrap")
    ASSERT_EQ(crypto_init(), 0);
RUN(test_create_open_roundtrip);
RUN(test_open_wrong_pin_fails);
RUN(test_rewrap_changes_pin);
TEST_MAIN_END
