/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "testutil.h"
#include "tokenstore.h"
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

static const char *tmpdir = "/tmp/test_reliquary_tokenstore";

static void
cleanup(void)
{
	char cmd[512];
	snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
	ASSERT_EQ(system(cmd), 0);
}

static void
setup(void)
{
	cleanup();
	mkdir(tmpdir, 0700);
}

TEST(test_token_path)
{
	char path[512];
	tokenstore_token_path(tmpdir, "my-key", path, sizeof(path));
	char expected[512];
	snprintf(expected, sizeof(expected), "%s/my-key", tmpdir);
	ASSERT_STR_EQ(path, expected);
}

TEST(test_exists_no)
{
	setup();
	ASSERT_EQ(tokenstore_exists(tmpdir, "nonexistent"), 0);
	cleanup();
}

TEST(test_create_and_exists)
{
	setup();
	ASSERT_EQ(tokenstore_create(tmpdir, "test-token"), 0);
	ASSERT_EQ(tokenstore_exists(tmpdir, "test-token"), 1);
	char path[512];
	tokenstore_token_path(tmpdir, "test-token", path, sizeof(path));
	struct stat st;
	ASSERT_EQ(stat(path, &st), 0);
	ASSERT(S_ISDIR(st.st_mode));
	cleanup();
}

TEST(test_create_duplicate_fails)
{
	setup();
	ASSERT_EQ(tokenstore_create(tmpdir, "dup"), 0);
	ASSERT_EQ(tokenstore_create(tmpdir, "dup"), -1);
	cleanup();
}

TEST(test_list_empty)
{
	setup();
	char labels[16][256];
	int n = tokenstore_list(tmpdir, labels, 16);
	ASSERT_EQ(n, 0);
	cleanup();
}

TEST(test_list_tokens)
{
	setup();
	tokenstore_create(tmpdir, "alpha");
	tokenstore_create(tmpdir, "beta");
	tokenstore_create(tmpdir, "gamma");
	char labels[16][256];
	int n = tokenstore_list(tmpdir, labels, 16);
	ASSERT_EQ(n, 3);
	int found_a = 0, found_b = 0, found_g = 0;
	for (int i = 0; i < n; i++) {
		if (strcmp(labels[i], "alpha") == 0)
			found_a = 1;
		if (strcmp(labels[i], "beta") == 0)
			found_b = 1;
		if (strcmp(labels[i], "gamma") == 0)
			found_g = 1;
	}
	ASSERT(found_a && found_b && found_g);
	cleanup();
}

TEST(test_list_truncates)
{
	setup();
	tokenstore_create(tmpdir, "a");
	tokenstore_create(tmpdir, "b");
	tokenstore_create(tmpdir, "c");
	char labels[2][256];
	int n = tokenstore_list(tmpdir, labels, 2);
	ASSERT_EQ(n, 2);
	cleanup();
}

TEST(test_remove)
{
	setup();
	tokenstore_create(tmpdir, "doomed");
	ASSERT_EQ(tokenstore_exists(tmpdir, "doomed"), 1);
	ASSERT_EQ(tokenstore_remove(tmpdir, "doomed"), 0);
	ASSERT_EQ(tokenstore_exists(tmpdir, "doomed"), 0);
	cleanup();
}

TEST(test_remove_nonexistent)
{
	setup();
	ASSERT_EQ(tokenstore_remove(tmpdir, "ghost"), -1);
	cleanup();
}

TEST_MAIN_BEGIN("test_tokenstore")
    RUN(test_token_path);
RUN(test_exists_no);
RUN(test_create_and_exists);
RUN(test_create_duplicate_fails);
RUN(test_list_empty);
RUN(test_list_tokens);
RUN(test_list_truncates);
RUN(test_remove);
RUN(test_remove_nonexistent);
TEST_MAIN_END
