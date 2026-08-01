/* SPDX-License-Identifier: GPL-2.0-or-later */

#define _POSIX_C_SOURCE 200809L
#include "testutil.h"
#include "testhelper.h"
#include "cmd_admin.h"
#include "log.h"
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *store = "/tmp/test_reliquary_secret_safety";
static char errfile[] = "/tmp/test_reliquary_secret_safety_err_XXXXXX";
static int saved_stderr = -1;

static const unsigned char canary[] = "CANARYSECRETPAYLOADCANARYSECRET!";
#define CANARY_LEN (sizeof(canary) - 1)

static void
cleanup(void)
{
	char cmd[512];
	snprintf(cmd, sizeof(cmd), "rm -rf %s", store);
	ASSERT_EQ(system(cmd), 0);
}

static void
setup(void)
{
	cleanup();
	mkdir(store, 0700);
}

/* Redirect this process's stderr (fd 2) to a fresh temp file. Must be called
   BEFORE test_server_start() forks, so the child inherits the redirected
   fd. */
static void
stderr_capture_start(void)
{
	static char tmpl[] = "/tmp/test_reliquary_secret_safety_err_XXXXXX";
	memcpy(errfile, tmpl, sizeof(tmpl));
	int fd = mkstemp(errfile);
	ASSERT(fd >= 0);
	saved_stderr = dup(STDERR_FILENO);
	ASSERT(saved_stderr >= 0);
	ASSERT_EQ(dup2(fd, STDERR_FILENO), STDERR_FILENO);
	close(fd);
}

/* Restore this process's stderr and return the captured bytes as a
   malloc'd, null-terminated string. Caller frees. */
static char *
stderr_capture_stop(void)
{
	fflush(stderr);
	ASSERT_EQ(dup2(saved_stderr, STDERR_FILENO), STDERR_FILENO);
	close(saved_stderr);
	saved_stderr = -1;

	FILE *f = fopen(errfile, "rb");
	ASSERT_NOT_NULL(f);
	ASSERT_EQ(fseek(f, 0, SEEK_END), 0);
	long sz = ftell(f);
	ASSERT(sz >= 0);
	ASSERT_EQ(fseek(f, 0, SEEK_SET), 0);
	char *buf = malloc((size_t)sz + 1);
	ASSERT_NOT_NULL(buf);
	size_t n = fread(buf, 1, (size_t)sz, f);
	buf[n] = '\0';
	fclose(f);
	unlink(errfile);
	return buf;
}

struct value_inq_fixture {
	assuan_context_t ctx;
	const unsigned char *data;
	size_t data_len;
};

static gpg_error_t
value_inq_cb(void *opaque, const char *name)
{
	struct value_inq_fixture *f = opaque;
	(void)name;		/* SIGN only raises VALUE here (already logged in) */
	return assuan_send_data(f->ctx, f->data, f->data_len);
}

struct byte_sink {
	size_t len;
};

static gpg_error_t
byte_sink_cb(void *opaque, const void *data, size_t len)
{
	(void)data;
	((struct byte_sink *)opaque)->len += len;
	return 0;
}

TEST(test_sign_payload_never_logged)
{
	setup();

	log_init(2);
	stderr_capture_start();

	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);

	ASSERT_EQ(test_command_ok(ctx, "INIT_STORE adminpin"), (gpg_error_t) 0);
	ASSERT_EQ(test_command_ok(ctx, "CREATE_TOKEN secsafe 1234 adminpin"),
		  (gpg_error_t) 0);
	ASSERT_EQ(test_command_ok(ctx, "OPEN_SESSION secsafe"), (gpg_error_t) 0);
	ASSERT_EQ(test_command_ok(ctx, "LOGIN 1234"), (gpg_error_t) 0);
	ASSERT_EQ(test_command_ok(ctx, "GENKEY 0 ed25519"), (gpg_error_t) 0);

	struct value_inq_fixture vf = { ctx, canary, CANARY_LEN };
	struct byte_sink sink = { 0 };
	ASSERT_EQ(assuan_transact(ctx, "SIGN 0 sign.eddsa", byte_sink_cb, &sink,
				  value_inq_cb, &vf, NULL, NULL),
		  (gpg_error_t) 0);
	ASSERT(sink.len > 0);

	test_server_stop(ctx, pid);

	char *log = stderr_capture_stop();

	/* Proof the SIGN actually ran and was logged, so the absence checks
	   below are meaningful rather than vacuous. */
	ASSERT(strstr(log, "debug1: SIGN slot=0 mech=sign.eddsa -> ok") != NULL);
	ASSERT(strstr(log, "debug2: SIGN in=32 out=") != NULL);

	/* PIN must not leak (already covered by test_log_lines, reasserted
	   here since this test also logs in). */
	ASSERT(strstr(log, "1234") == NULL);

	/* The crypto payload itself -- raw ASCII -- must never appear. */
	ASSERT(strstr(log, (const char *)canary) == NULL);

	/* Nor its lowercase-hex encoding, in case some future call site hex-
	   dumps the buffer instead of printing it verbatim. */
	char hexbuf[CANARY_LEN * 2 + 1];
	for (size_t i = 0; i < CANARY_LEN; i++)
		snprintf(hexbuf + i * 2, 3, "%02x", canary[i]);
	hexbuf[CANARY_LEN * 2] = '\0';
	ASSERT(strstr(log, hexbuf) == NULL);

	free(log);
	log_init(0);
	cleanup();
}

TEST_MAIN_BEGIN("test_secret_safety")
    RUN(test_sign_payload_never_logged);
TEST_MAIN_END
