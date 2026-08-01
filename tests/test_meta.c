/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "testutil.h"
#include "meta.h"
#include <gcrypt.h>
#include <unistd.h>
#include <string.h>

static const char *tmpfile_path = "/tmp/test_reliquary_metadata";

static void
cleanup(void)
{
	unlink(tmpfile_path);
}

TEST(test_write_and_read)
{
	cleanup();
	token_meta_t m = {
		.version = 1,
		.label = "test-token",
		.algorithm = {"rsa2048", NULL, NULL},
		.public_key_hex = {"aabbccdd", NULL, NULL},
		.created_at = "2026-04-09T12:00:00Z",
		.pin_max_retries = 3,
	};
	ASSERT_EQ(meta_write(tmpfile_path, &m), 0);

	token_meta_t r = { 0 };
	ASSERT_EQ(meta_read(tmpfile_path, &r), 0);
	ASSERT_EQ(r.version, 1);
	ASSERT_STR_EQ(r.label, "test-token");
	ASSERT_STR_EQ(r.algorithm[RELIQUARY_SLOT_SIGN], "rsa2048");
	ASSERT_STR_EQ(r.public_key_hex[RELIQUARY_SLOT_SIGN], "aabbccdd");
	ASSERT_NULL(r.algorithm[RELIQUARY_SLOT_ENCRYPT]);
	ASSERT_NULL(r.algorithm[RELIQUARY_SLOT_AUTH]);
	ASSERT_NULL(r.public_key_hex[RELIQUARY_SLOT_ENCRYPT]);
	ASSERT_NULL(r.public_key_hex[RELIQUARY_SLOT_AUTH]);
	ASSERT_STR_EQ(r.created_at, "2026-04-09T12:00:00Z");
	ASSERT_EQ(r.pin_max_retries, 3);
	meta_free(&r);
	cleanup();
}

TEST(test_write_with_all_slots)
{
	cleanup();
	token_meta_t m = {
		.version = 1,
		.label = "multi-token",
		.algorithm = {"rsa2048", "nistp256", "ed25519"},
		.public_key_hex = {"aa", "bb", "cc"},
		.created_at = "2026-04-09T12:00:00Z",
		.pin_max_retries = 3,
	};
	ASSERT_EQ(meta_write(tmpfile_path, &m), 0);

	token_meta_t r = { 0 };
	ASSERT_EQ(meta_read(tmpfile_path, &r), 0);
	ASSERT_STR_EQ(r.algorithm[RELIQUARY_SLOT_SIGN], "rsa2048");
	ASSERT_STR_EQ(r.algorithm[RELIQUARY_SLOT_ENCRYPT], "nistp256");
	ASSERT_STR_EQ(r.algorithm[RELIQUARY_SLOT_AUTH], "ed25519");
	ASSERT_STR_EQ(r.public_key_hex[RELIQUARY_SLOT_SIGN], "aa");
	ASSERT_STR_EQ(r.public_key_hex[RELIQUARY_SLOT_ENCRYPT], "bb");
	ASSERT_STR_EQ(r.public_key_hex[RELIQUARY_SLOT_AUTH], "cc");
	meta_free(&r);
	cleanup();
}

TEST(test_allowed_mechs_roundtrip)
{
	cleanup();
	token_meta_t m = {
		.version = 1,
		.label = "mechs-token",
		.algorithm = {"rsa2048", "nistp256", NULL},
		.allowed_mechs = {"sign.rsa-pkcs1,sign.rsa-pss", NULL, NULL},
		.created_at = "2026-04-09T12:00:00Z",
		.pin_max_retries = 3,
	};
	ASSERT_EQ(meta_write(tmpfile_path, &m), 0);

	token_meta_t r = { 0 };
	ASSERT_EQ(meta_read(tmpfile_path, &r), 0);
	ASSERT_STR_EQ(r.allowed_mechs[RELIQUARY_SLOT_SIGN],
		      "sign.rsa-pkcs1,sign.rsa-pss");
	ASSERT_NULL(r.allowed_mechs[RELIQUARY_SLOT_ENCRYPT]);
	ASSERT_NULL(r.allowed_mechs[RELIQUARY_SLOT_AUTH]);
	meta_free(&r);
	cleanup();
}

TEST(test_read_nonexistent_fails)
{
	token_meta_t r = { 0 };
	ASSERT_EQ(meta_read("/tmp/nonexistent_reliquary_meta", &r), -1);
}

TEST(test_meta_free_zeroed_noop)
{
	token_meta_t r = { 0 };
	meta_free(&r);
}

TEST(test_overwrite)
{
	cleanup();
	token_meta_t m1 = {
		.version = 1,
		.label = "tok",
		.algorithm = {"rsa2048", NULL, NULL},
		.public_key_hex = {"aa", NULL, NULL},
		.created_at = "2026-04-09T12:00:00Z",
		.pin_max_retries = 3,
	};
	ASSERT_EQ(meta_write(tmpfile_path, &m1), 0);

	m1.pin_max_retries = 5;
	ASSERT_EQ(meta_write(tmpfile_path, &m1), 0);

	token_meta_t r = { 0 };
	ASSERT_EQ(meta_read(tmpfile_path, &r), 0);
	ASSERT_EQ(r.pin_max_retries, 5);
	meta_free(&r);
	cleanup();
}

TEST(test_meta_version_is_one)
{
	cleanup();
	token_meta_t m = {
		.version = META_VERSION,
		.label = "vtok",
		.algorithm = {"rsa2048", NULL, NULL},
		.public_key_hex = {"aa", NULL, NULL},
		.created_at = "2026-07-29T00:00:00Z",
		.pin_max_retries = 3,
	};
	ASSERT_EQ(meta_write(tmpfile_path, &m), 0);

	token_meta_t r = { 0 };
	ASSERT_EQ(meta_read(tmpfile_path, &r), 0);
	ASSERT_EQ(r.version, 1);
	meta_free(&r);
	cleanup();
}

TEST_MAIN_BEGIN("test_meta")
    RUN(test_write_and_read);
RUN(test_write_with_all_slots);
RUN(test_allowed_mechs_roundtrip);
RUN(test_read_nonexistent_fails);
RUN(test_meta_free_zeroed_noop);
RUN(test_overwrite);
RUN(test_meta_version_is_one);
TEST_MAIN_END
