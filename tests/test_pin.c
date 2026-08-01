/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "testutil.h"
#include "pin.h"
#include "meta.h"
#include "crypto.h"
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *tmpdir = "/tmp/test_reliquary_pin";

static void
cleanup(void)
{
	char path[256];
	snprintf(path, sizeof(path), "%s/metadata", tmpdir);
	unlink(path);
	snprintf(path, sizeof(path), "%s/state", tmpdir);
	unlink(path);
	rmdir(tmpdir);
}

static void
setup_token(int pin_max_retries)
{
	cleanup();
	mkdir(tmpdir, 0700);

	char mpath[256];
	snprintf(mpath, sizeof(mpath), "%s/metadata", tmpdir);

	token_meta_t m = {
		.version = 1,.label = "test",
		.algorithm = {"rsa2048", NULL, NULL}
		,
		.public_key_hex = {"aa", NULL, NULL}
		,
		.created_at = "2026-04-09T00:00:00Z",
		.pin_max_retries = pin_max_retries,
	};
	meta_write(mpath, &m);
}

TEST(test_is_locked_false_with_retries_remaining)
{
	setup_token(3);
	ASSERT(!pin_is_locked(tmpdir));
	cleanup();
}

TEST(test_is_locked_true_when_state_retries_exhausted)
{
	setup_token(3);
	token_state_t st = { .pin_retries = 0, .disconnected = 0 };
	state_write(tmpdir, &st);
	ASSERT(pin_is_locked(tmpdir));
	cleanup();
}

TEST(test_is_locked_falls_back_to_meta_max_retries)
{
	setup_token(0);
	/* No state file written; pin_is_locked falls back to
	 * meta.pin_max_retries, which is 0 here. */
	ASSERT(pin_is_locked(tmpdir));
	cleanup();
}

TEST(test_create_hash_produces_hex_strings)
{
	char *salt_hex = NULL, *hash_hex = NULL;
	ASSERT_EQ(pin_create_hash("1234", 4, &salt_hex, &hash_hex), 0);
	ASSERT_NOT_NULL(salt_hex);
	ASSERT_NOT_NULL(hash_hex);
	ASSERT_EQ(strlen(salt_hex), (size_t)CRYPTO_KDF_SALT_LEN * 2);
	ASSERT_EQ(strlen(hash_hex), (size_t)CRYPTO_GCM_KEY_LEN * 2);
	free(salt_hex);
	free(hash_hex);
}

TEST(test_create_hash_is_randomized)
{
	char *salt1 = NULL, *hash1 = NULL;
	char *salt2 = NULL, *hash2 = NULL;
	ASSERT_EQ(pin_create_hash("1234", 4, &salt1, &hash1), 0);
	ASSERT_EQ(pin_create_hash("1234", 4, &salt2, &hash2), 0);
	ASSERT(strcmp(salt1, salt2) != 0);
	free(salt1);
	free(hash1);
	free(salt2);
	free(hash2);
}

TEST_MAIN_BEGIN("test_pin")
    ASSERT_EQ(crypto_init(), 0);
RUN(test_is_locked_false_with_retries_remaining);
RUN(test_is_locked_true_when_state_retries_exhausted);
RUN(test_is_locked_falls_back_to_meta_max_retries);
RUN(test_create_hash_produces_hex_strings);
RUN(test_create_hash_is_randomized);
TEST_MAIN_END
