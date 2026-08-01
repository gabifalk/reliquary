/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _POSIX_C_SOURCE 200809L
#include "testutil.h"
#include "testhelper.h"
#include "client.h"
#include "tokenstore.h"
#include "hex.h"
#include <sys/stat.h>
#include <stdlib.h>
#include <gcrypt.h>

static const char *store = "/tmp/test_reliquary_tools";

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

static gpg_error_t
tools_status_collect(void *opaque, const char *line)
{
	char *buf = opaque;
	strncat(buf, line, 1024 - strlen(buf) - 2);
	strncat(buf, "\n", 1024 - strlen(buf) - 1);
	return 0;
}

TEST(test_create_and_list_via_client)
{
	setup();
	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);

	ASSERT_EQ(client_command_ok(ctx, "INIT_STORE adminpin"),
		  (gpg_error_t) 0);
	gpg_error_t err = client_command_ok(ctx, "CREATE_TOKEN mytoken 1234 adminpin");
	ASSERT_EQ(err, (gpg_error_t) 0);

	static char toolbuf[1024];
	toolbuf[0] = '\0';
	err = client_command_status(ctx, "LIST_TOKENS", tools_status_collect,
				     toolbuf);
	ASSERT_EQ(err, (gpg_error_t) 0);
	ASSERT(strstr(toolbuf, "mytoken") != NULL);

	test_server_stop(ctx, pid);
	cleanup();
}

TEST(test_create_login_sign_via_client)
{
	setup();
	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);

	ASSERT_EQ(client_command_ok(ctx, "INIT_STORE adminpin"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "CREATE_TOKEN signkey 4321 adminpin"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "OPEN_SESSION signkey"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "LOGIN 4321"), (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok
		  (ctx, "GENKEY 0 rsa2048"), (gpg_error_t) 0);

	unsigned char sign_input[51];
	size_t sign_input_len = 0;
	ASSERT_EQ(hex_decode
		  ("3031300d060960864801650304020105000420aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		   sign_input, sizeof(sign_input), &sign_input_len), 0);

	unsigned char *data = NULL;
	size_t data_len = 0;
	gpg_error_t err = client_command_data_reply(ctx, "SIGN 0 sign.rsa-pkcs1",
						    sign_input, sign_input_len,
						    &data, &data_len);
	ASSERT_EQ(err, (gpg_error_t) 0);
	ASSERT_NOT_NULL(data);
	ASSERT(data_len > 0);
	free(data);

	ASSERT_EQ(client_command_ok(ctx, "LOGOUT"), (gpg_error_t) 0);
	test_server_stop(ctx, pid);
	cleanup();
}

TEST(test_change_pin_via_client)
{
	setup();
	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);

	ASSERT_EQ(client_command_ok(ctx, "INIT_STORE adminpin"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "CREATE_TOKEN pinkey oldpin adminpin"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "OPEN_SESSION pinkey"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "LOGIN oldpin"), (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "CHANGE_PIN newpin"), (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "LOGOUT"), (gpg_error_t) 0);

	ASSERT_EQ(client_command_ok(ctx, "LOGIN newpin"), (gpg_error_t) 0);

	ASSERT_EQ(client_command_ok(ctx, "LOGOUT"), (gpg_error_t) 0);
	gpg_error_t err = client_command_ok(ctx, "LOGIN oldpin");
	ASSERT_NEQ(err, (gpg_error_t) 0);

	test_server_stop(ctx, pid);
	cleanup();
}

/* Build a fresh RSA-2048 private-key sexp, IMPORT_SLOT it (sexp sent
 * out-of-band via INQUIRE KEYDATA) into an existing token, then confirm the
 * imported key can SIGN. */
TEST(test_import_slot_login_sign_via_client)
{
	setup();
	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);

	ASSERT_EQ(client_command_ok(ctx, "INIT_STORE adminpin"), (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "CREATE_TOKEN imp 4321 adminpin"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "OPEN_SESSION imp"), (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "LOGIN 4321"), (gpg_error_t) 0);

	/* Generate a key pair to import. */
	gcry_sexp_t params = NULL, kp = NULL;
	ASSERT_EQ(gcry_sexp_build(&params, NULL, "(genkey (rsa (nbits %u)))",
				  (unsigned)2048), 0);
	ASSERT_EQ(gcry_pk_genkey(&kp, params), 0);
	gcry_sexp_release(params);
	size_t clen = gcry_sexp_sprint(kp, GCRYSEXP_FMT_CANON, NULL, 0);
	unsigned char *canon = malloc(clen);
	ASSERT_NOT_NULL(canon);
	clen = gcry_sexp_sprint(kp, GCRYSEXP_FMT_CANON, canon, clen);
	gcry_sexp_release(kp);

	/* Send the sexp out-of-band -- it far exceeds the Assuan line limit. */
	ASSERT_EQ(client_command_with_data(ctx, "IMPORT_SLOT 0",
					   canon, clen), (gpg_error_t) 0);
	free(canon);

	unsigned char sign_input[51];
	size_t sign_input_len = 0;
	ASSERT_EQ(hex_decode
		  ("3031300d060960864801650304020105000420aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		   sign_input, sizeof(sign_input), &sign_input_len), 0);

	unsigned char *data = NULL;
	size_t data_len = 0;
	gpg_error_t err = client_command_data_reply(ctx, "SIGN 0 sign.rsa-pkcs1",
						    sign_input, sign_input_len,
						    &data, &data_len);
	ASSERT_EQ(err, (gpg_error_t) 0);
	ASSERT_NOT_NULL(data);
	ASSERT(data_len > 0);
	free(data);

	ASSERT_EQ(client_command_ok(ctx, "LOGOUT"), (gpg_error_t) 0);
	test_server_stop(ctx, pid);
	cleanup();
}

/* Inquire callback for test_sign_without_login_triggers_needpin: answers
   NEEDPIN with the token PIN and VALUE with the data to sign, driving the
   two-step NEEDPIN-then-VALUE inquiry sequence ensure_logged_in() plus the
   SIGN data fetch produce when SIGN is issued on an OPEN-but-not-LOGGED-IN
   session (the state the scd-proxy will be in when it relies on
   NEEDPIN-on-demand instead of an explicit LOGIN). */
struct needpin_sign_ctx {
	assuan_context_t actx;
	const char *pin;
	const unsigned char *data;
	size_t data_len;
};

static gpg_error_t
needpin_sign_inquire_cb(void *opaque, const char *name)
{
	struct needpin_sign_ctx *c = opaque;
	if (strncmp(name, "NEEDPIN", 7) == 0)
		return assuan_send_data(c->actx, c->pin, strlen(c->pin));
	if (strcmp(name, "VALUE") == 0)
		return assuan_send_data(c->actx, c->data, c->data_len);
	return gpg_error(GPG_ERR_ASS_UNKNOWN_INQUIRE);
}

TEST(test_sign_without_login_triggers_needpin)
{
	setup();
	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);

	ASSERT_EQ(client_command_ok(ctx, "INIT_STORE adminpin"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "CREATE_TOKEN needpinkey 9999 adminpin"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "OPEN_SESSION needpinkey"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "LOGIN 9999"), (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "GENKEY 0 rsa2048"), (gpg_error_t) 0);
	/* LOGOUT drops sess->logged_in and the loaded key material, but
	   leaves the token OPEN (token_label/token_dir stay set) -- exactly
	   the state of a proxy session that never issued LOGIN. */
	ASSERT_EQ(client_command_ok(ctx, "LOGOUT"), (gpg_error_t) 0);

	unsigned char sign_input[51];
	size_t sign_input_len = 0;
	ASSERT_EQ(hex_decode
		  ("3031300d060960864801650304020105000420aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		   sign_input, sizeof(sign_input), &sign_input_len), 0);

	struct needpin_sign_ctx nc = { ctx, "9999", sign_input, sign_input_len };
	struct _collect_data cd = { NULL, 0, 0 };
	gpg_error_t err = assuan_transact(ctx, "SIGN 0 sign.rsa-pkcs1",
					  _data_cb, &cd,
					  needpin_sign_inquire_cb, &nc,
					  NULL, NULL);
	ASSERT_EQ(err, (gpg_error_t) 0);
	ASSERT_NOT_NULL(cd.buf);
	ASSERT(cd.len > 0);
	free(cd.buf);

	test_server_stop(ctx, pid);
	cleanup();
}

TEST_MAIN_BEGIN("test_tools")
    ASSERT_EQ(crypto_init(), 0);
RUN(test_create_and_list_via_client);
RUN(test_create_login_sign_via_client);
RUN(test_change_pin_via_client);
RUN(test_import_slot_login_sign_via_client);
RUN(test_sign_without_login_triggers_needpin);
TEST_MAIN_END
