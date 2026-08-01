/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "testutil.h"
#include "session.h"
#include "tokenstore.h"
#include "keyfile.h"
#include "keywrap.h"
#include "meta.h"
#include "crypto.h"
#include "secmem.h"
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>

static const char *store = "/tmp/test_reliquary_session";

static void
cleanup(void)
{
	char cmd[512];
	snprintf(cmd, sizeof(cmd), "rm -rf %s", store);
	ASSERT_EQ(system(cmd), 0);
}

static void
setup_with_token(const char *label, const char *pin)
{
	cleanup();
	mkdir(store, 0700);
	tokenstore_create(store, label);

	char tpath[512], kpath[540], mpath[528];
	tokenstore_token_path(store, label, tpath, sizeof(tpath));
	snprintf(kpath, sizeof(kpath), "%s/sign.key.enc", tpath);
	snprintf(mpath, sizeof(mpath), "%s/metadata", tpath);

	const unsigned char key_data[] = "fake-rsa-key-sexp";
	keywrap_create(tpath, pin, strlen(pin));
	unsigned char mk[KEYWRAP_MK_LEN];
	keywrap_open(tpath, pin, strlen(pin), mk);
	keyfile_seal(kpath, mk, key_data, sizeof(key_data));

	token_meta_t m = {
		.version = 1,.label = (char *)label,
		.algorithm = {"rsa2048", NULL, NULL},
		.public_key_hex = {"aabb", NULL, NULL},
		.created_at = "2026-04-09T00:00:00Z",
		.pin_max_retries = 3,
	};
	meta_write(mpath, &m);

	token_state_t st = { .pin_retries = 3, .disconnected = 0 };
	state_write(tpath, &st);
}

TEST(test_init_and_destroy)
{
	session_t sess;
	session_init(&sess, 1000, store);
	ASSERT_EQ(sess.uid, (uid_t)1000);
	ASSERT_EQ(sess.logged_in, 0);
	ASSERT_NULL(sess.key[0]);
	ASSERT_EQ(sess.token_label[0], '\0');
	session_destroy(&sess);
}

TEST(test_open_existing_token)
{
	setup_with_token("mykey", "1234");
	session_t sess;
	session_init(&sess, 1000, store);
	ASSERT_EQ(session_open(&sess, "mykey"), 0);
	ASSERT_STR_EQ(sess.token_label, "mykey");
	ASSERT_EQ(sess.logged_in, 0);
	session_destroy(&sess);
	cleanup();
}

TEST(test_open_nonexistent_fails)
{
	cleanup();
	mkdir(store, 0700);
	session_t sess;
	session_init(&sess, 1000, store);
	ASSERT_EQ(session_open(&sess, "nope"), -1);
	ASSERT_EQ(sess.token_label[0], '\0');
	session_destroy(&sess);
	cleanup();
}

TEST(test_login_correct_pin)
{
	setup_with_token("mykey", "1234");
	session_t sess;
	session_init(&sess, 1000, store);
	session_open(&sess, "mykey");
	ASSERT_EQ(session_login(&sess, "1234", 4), 0);
	ASSERT_EQ(sess.logged_in, 1);
	ASSERT_NOT_NULL(sess.key[0]);
	ASSERT(sess.key_len[0] > 0);
	ASSERT_STR_EQ(sess.algorithm[0], "rsa2048");
	session_destroy(&sess);
	cleanup();
}

TEST(test_login_wrong_pin)
{
	setup_with_token("mykey", "1234");
	session_t sess;
	session_init(&sess, 1000, store);
	session_open(&sess, "mykey");
	ASSERT_EQ(session_login(&sess, "wrong", 5), -1);
	ASSERT_EQ(sess.logged_in, 0);
	ASSERT_NULL(sess.key[0]);
	session_destroy(&sess);
	cleanup();
}

TEST(test_login_without_open_fails)
{
	session_t sess;
	session_init(&sess, 1000, store);
	ASSERT_EQ(session_login(&sess, "1234", 4), -3);
	session_destroy(&sess);
}

TEST(test_logout_zeros_key)
{
	setup_with_token("mykey", "1234");
	session_t sess;
	session_init(&sess, 1000, store);
	session_open(&sess, "mykey");
	session_login(&sess, "1234", 4);
	ASSERT_EQ(sess.logged_in, 1);
	session_logout(&sess);
	ASSERT_EQ(sess.logged_in, 0);
	ASSERT_NULL(sess.key[0]);
	ASSERT_EQ(sess.key_len[0], (size_t)0);
	ASSERT_STR_EQ(sess.token_label, "mykey");
	session_destroy(&sess);
	cleanup();
}

TEST(test_close_clears_everything)
{
	setup_with_token("mykey", "1234");
	session_t sess;
	session_init(&sess, 1000, store);
	session_open(&sess, "mykey");
	session_login(&sess, "1234", 4);
	session_close(&sess);
	ASSERT_EQ(sess.logged_in, 0);
	ASSERT_NULL(sess.key[0]);
	ASSERT_EQ(sess.token_label[0], '\0');
	session_destroy(&sess);
	cleanup();
}

TEST_MAIN_BEGIN("test_session")
    ASSERT_EQ(crypto_init(), 0);
RUN(test_init_and_destroy);
RUN(test_open_existing_token);
RUN(test_open_nonexistent_fails);
RUN(test_login_correct_pin);
RUN(test_login_wrong_pin);
RUN(test_login_without_open_fails);
RUN(test_logout_zeros_key);
RUN(test_close_clears_everything);
TEST_MAIN_END
