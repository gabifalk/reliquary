/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "testutil.h"
#include "keyfile.h"
#include "crypto.h"
#include "secmem.h"
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *tmpfile_path = "/tmp/test_reliquary_keyfile.enc";

static void
cleanup(void)
{
	unlink(tmpfile_path);
}

static const unsigned char TEST_KEY32[32] = {
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
};

TEST(test_seal_open_roundtrip)
{
	cleanup();
	const unsigned char data[] = "master-key-sealed-material";
	ASSERT_EQ(keyfile_seal(tmpfile_path, TEST_KEY32, data, sizeof(data)), 0);

	unsigned char *out = NULL;
	size_t out_len = 0;
	ASSERT_EQ(keyfile_open(tmpfile_path, TEST_KEY32, &out, &out_len), 0);
	ASSERT_NOT_NULL(out);
	ASSERT_EQ(out_len, sizeof(data));
	ASSERT_MEM_EQ(out, data, sizeof(data));
	secure_free(out, out_len);
	cleanup();
}

TEST(test_seal_open_wrong_key_fails)
{
	cleanup();
	unsigned char wrong[32];
	memcpy(wrong, TEST_KEY32, 32);
	wrong[0] ^= 0xff;
	const unsigned char data[] = "secret";
	ASSERT_EQ(keyfile_seal(tmpfile_path, TEST_KEY32, data, sizeof(data)), 0);

	unsigned char *out = NULL;
	size_t out_len = 0;
	ASSERT_EQ(keyfile_open(tmpfile_path, wrong, &out, &out_len), -1);
	ASSERT_NULL(out);
	cleanup();
}

TEST_MAIN_BEGIN("test_keyfile")
    ASSERT_EQ(crypto_init(), 0);
RUN(test_seal_open_roundtrip);
RUN(test_seal_open_wrong_key_fails);
TEST_MAIN_END
