/* SPDX-License-Identifier: GPL-2.0-or-later */

#define _GNU_SOURCE
#include "log.h"
#include "testutil.h"
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

static int
capture_begin(int *readfd)
{
	char path[] = "/tmp/reliquary-log-test-XXXXXX";
	int tf = mkstemp(path);
	ASSERT(tf >= 0);
	unlink(path);
	int saved = dup(STDERR_FILENO);
	ASSERT(saved >= 0);
	ASSERT(dup2(tf, STDERR_FILENO) >= 0);
	*readfd = tf;
	return saved;
}

static void
capture_end(int saved)
{
	fflush(stderr);
	dup2(saved, STDERR_FILENO);
	close(saved);
}

static size_t
read_all(int fd, char *buf, size_t cap)
{
	lseek(fd, 0, SEEK_SET);
	ssize_t n = read(fd, buf, cap - 1);
	if (n < 0)
		n = 0;
	buf[n] = '\0';
	return (size_t)n;
}

TEST(test_level_0_debug_silent)
{
	log_init(0);
	int rfd, saved = capture_begin(&rfd);
	log_debug("hidden-d1");
	log_debug2("hidden-d2");
	log_error("shown-err");
	capture_end(saved);
	char buf[512];
	read_all(rfd, buf, sizeof(buf));
	close(rfd);
	ASSERT(strstr(buf, "hidden-d1") == NULL);
	ASSERT(strstr(buf, "hidden-d2") == NULL);
	ASSERT(strstr(buf, "shown-err") != NULL);
}

TEST(test_level_1_debug_only)
{
	log_init(1);
	int rfd, saved = capture_begin(&rfd);
	log_debug("d1-visible");
	log_debug2("d2-hidden");
	capture_end(saved);
	char buf[512];
	read_all(rfd, buf, sizeof(buf));
	close(rfd);
	ASSERT(strstr(buf, "d1-visible") != NULL);
	ASSERT(strstr(buf, "d2-hidden") == NULL);
}

TEST(test_level_2_both)
{
	log_init(2);
	int rfd, saved = capture_begin(&rfd);
	log_debug("d1");
	log_debug2("d2");
	capture_end(saved);
	char buf[512];
	read_all(rfd, buf, sizeof(buf));
	close(rfd);
	ASSERT(strstr(buf, "d1") != NULL);
	ASSERT(strstr(buf, "d2") != NULL);
}

TEST(test_clamp_and_get_level)
{
	log_init(5);
	ASSERT_EQ(log_get_level(), 2);
	log_init(-3);
	ASSERT_EQ(log_get_level(), 0);
}

TEST(test_format_prefix_and_pid)
{
	log_init(1);
	int rfd, saved = capture_begin(&rfd);
	log_debug("val=%d", 42);
	log_error("boom");
	capture_end(saved);
	char buf[512];
	read_all(rfd, buf, sizeof(buf));
	close(rfd);
	char pidpat[64];
	snprintf(pidpat, sizeof(pidpat), "%s[%d]:",
		 program_invocation_short_name, (int)getpid());
	ASSERT(strstr(buf, "debug1: val=42\n") != NULL);
	ASSERT(strstr(buf, pidpat) != NULL);
	ASSERT(strstr(buf, "boom\n") != NULL);
}

TEST_MAIN_BEGIN("log")
	RUN(test_level_0_debug_silent);
	RUN(test_level_1_debug_only);
	RUN(test_level_2_both);
	RUN(test_clamp_and_get_level);
	RUN(test_format_prefix_and_pid);
TEST_MAIN_END
