/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _POSIX_C_SOURCE 200809L
#include "testutil.h"
#include "testhelper.h"
#include "tokenstore.h"
#include "keyfile.h"
#include "keywrap.h"
#include "meta.h"
#include "pin.h"
#include "crypto_ec.h"
#include "crypto_rsa.h"
#include "cmd_admin.h"
#include "session.h"
#include "crypto_op.h"
#include "secmem.h"
#include <gcrypt.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>

static const char *store = "/tmp/test_reliquary_daemon";

static int store_config_written = 0;

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
	store_config_written = 0;
}

static void
ensure_store_config(void)
{
	if (store_config_written)
		return;
	char path[768];
	snprintf(path, sizeof(path), "%s/config", store);
	char *salt_hex = NULL, *hash_hex = NULL;
	pin_create_hash("adminpin", 8, &salt_hex, &hash_hex);
	gcry_sexp_t root;
	gcry_sexp_build(&root, NULL,
			"(store-config (serial 0)"
			" (admin-pin-salt %s)"
			" (admin-pin-hash %s))",
			salt_hex, hash_hex);
	size_t len = gcry_sexp_sprint(root, GCRYSEXP_FMT_ADVANCED, NULL, 0);
	char *text = malloc(len);
	gcry_sexp_sprint(root, GCRYSEXP_FMT_ADVANCED, text, len);
	gcry_sexp_release(root);
	FILE *f = fopen(path, "w");
	fputs(text, f);
	fclose(f);
	free(text);
	free(salt_hex);
	free(hash_hex);
	store_config_written = 1;
}

static void
create_test_token(const char *label, const char *pin, const char *algo)
{
	ensure_store_config();
	tokenstore_create(store, label);
	char tpath[512], kpath[540], mpath[528];
	tokenstore_token_path(store, label, tpath, sizeof(tpath));
	snprintf(kpath, sizeof(kpath), "%s/sign.key.enc", tpath);
	snprintf(mpath, sizeof(mpath), "%s/metadata", tpath);
	const unsigned char fake_key[] = "fake-key-sexp";
	keywrap_create(tpath, pin, strlen(pin));
	unsigned char mk[KEYWRAP_MK_LEN];
	keywrap_open(tpath, pin, strlen(pin), mk);
	keyfile_seal(kpath, mk, fake_key, sizeof(fake_key));
	token_meta_t m = {
		.version = 1,.serial_num = 1,.label = (char *)label,
		.algorithm = {(char *)algo, NULL, NULL},
		.public_key_hex = {"aabb", NULL, NULL},
		.created_at = "2026-04-09T00:00:00Z",
		.pin_max_retries = 3,
	};
	meta_write(mpath, &m);

	token_state_t st = { .pin_retries = 3, .disconnected = 0 };
	state_write(tpath, &st);
}

TEST(test_connect_and_nop)
{
	setup();
	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);

	gpg_error_t err = test_command_ok(ctx, "NOP");
	ASSERT_EQ(err, (gpg_error_t) 0);

	test_server_stop(ctx, pid);
	cleanup();
}

TEST(test_unknown_command)
{
	setup();
	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);

	gpg_error_t err = test_command_ok(ctx, "BOGUS_COMMAND");
	ASSERT_NEQ(err, (gpg_error_t) 0);

	test_server_stop(ctx, pid);
	cleanup();
}

TEST(test_open_session)
{
	setup();
	create_test_token("mykey", "1234", "rsa2048");
	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);
	ASSERT_EQ(test_command_ok(ctx, "OPEN_SESSION mykey"), (gpg_error_t) 0);
	test_server_stop(ctx, pid);
	cleanup();
}

TEST(test_open_session_nonexistent)
{
	setup();
	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);
	gpg_error_t err = test_command_ok(ctx, "OPEN_SESSION ghost");
	ASSERT_NEQ(err, (gpg_error_t) 0);
	test_server_stop(ctx, pid);
	cleanup();
}

TEST(test_login_and_logout)
{
	setup();
	create_test_token("mykey", "1234", "rsa2048");
	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);
	ASSERT_EQ(test_command_ok(ctx, "OPEN_SESSION mykey"), (gpg_error_t) 0);
	ASSERT_EQ(test_command_ok(ctx, "LOGIN 1234"), (gpg_error_t) 0);
	ASSERT_EQ(test_command_ok(ctx, "LOGOUT"), (gpg_error_t) 0);
	test_server_stop(ctx, pid);
	cleanup();
}

TEST(test_login_wrong_pin)
{
	setup();
	create_test_token("mykey", "1234", "rsa2048");
	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);
	ASSERT_EQ(test_command_ok(ctx, "OPEN_SESSION mykey"), (gpg_error_t) 0);
	gpg_error_t err = test_command_ok(ctx, "LOGIN wrong");
	ASSERT_NEQ(err, (gpg_error_t) 0);
	test_server_stop(ctx, pid);
	cleanup();
}

struct login_inq_fixture {
	assuan_context_t ctx;
};

static gpg_error_t
login_inq_cb(void *opaque, const char *name)
{
	struct login_inq_fixture *f = opaque;
	if (strncmp(name, "NEEDPIN", 7) == 0)
		return assuan_send_data(f->ctx, "1234", 4);
	return gpg_error(GPG_ERR_ASS_UNKNOWN_INQUIRE);
}

/*
 * LOGIN with no inline PIN mirrors the scd-proxy's CHECKPIN->LOGIN
 * translation, which has no PIN to send inline and relies on the daemon
 * raising NEEDPIN on demand (like IMPORT_SLOT's, see
 * test_import_slot_needpin_on_demand).
 */
TEST(test_login_empty_needpin)
{
	setup();
	create_test_token("mykey", "1234", "rsa2048");
	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);
	ASSERT_EQ(test_command_ok(ctx, "OPEN_SESSION mykey"), (gpg_error_t) 0);

	struct login_inq_fixture f = { ctx };
	gpg_error_t err = assuan_transact(ctx, "LOGIN", NULL, NULL,
					  login_inq_cb, &f, NULL, NULL);
	ASSERT_EQ(err, (gpg_error_t) 0);

	/* Login succeeded: GENKEY, gated directly on sess->logged_in (no
	   NEEDPIN prompt of its own), now works -- a subsequent op sees the
	   session as logged in. */
	ASSERT_EQ(test_command_ok(ctx, "GENKEY 1 rsa2048"), (gpg_error_t) 0);

	test_server_stop(ctx, pid);
	cleanup();
}

TEST(test_list_tokens)
{
	setup();
	create_test_token("alpha", "1234", "rsa2048");
	create_test_token("beta", "1234", "nistp256");
	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);
	char *data = NULL;
	ASSERT_EQ(test_command_status(ctx, "LIST_TOKENS", &data),
		  (gpg_error_t) 0);
	ASSERT_NOT_NULL(data);
	ASSERT(strstr(data, "alpha") != NULL);
	ASSERT(strstr(data, "beta") != NULL);
	free(data);
	test_server_stop(ctx, pid);
	cleanup();
}

TEST(test_get_mechanism_list)
{
	setup();
	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);
	char *data = NULL;
	size_t data_len = 0;
	ASSERT_EQ(test_command(ctx, "GET_MECHANISM_LIST", &data, &data_len),
		  (gpg_error_t) 0);
	ASSERT_NOT_NULL(data);
	char *tmp = malloc(data_len + 1);
	memcpy(tmp, data, data_len);
	tmp[data_len] = '\0';
	ASSERT(strstr(tmp, "sign.rsa-pkcs1") != NULL);
	ASSERT(strstr(tmp, "sign.ecdsa") != NULL);
	free(tmp);
	free(data);
	test_server_stop(ctx, pid);
	cleanup();
}

TEST(test_get_attribute_slots_removed)
{
	setup();
	create_test_token("mykey", "1234", "rsa2048");
	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);
	ASSERT_EQ(test_command_ok(ctx, "OPEN_SESSION mykey"), (gpg_error_t) 0);

	/* Raw per-slot algorithm stays available for the client to format. */
	char *data = NULL;
	size_t data_len = 0;
	ASSERT_EQ(test_command(ctx, "GET_ATTRIBUTE algorithm.0", &data,
			       &data_len), (gpg_error_t) 0);
	ASSERT_NOT_NULL(data);
	char *tmp = malloc(data_len + 1);
	memcpy(tmp, data, data_len);
	tmp[data_len] = '\0';
	ASSERT(strstr(tmp, "rsa2048") != NULL);
	free(tmp);
	free(data);

	/* An empty slot reports not-found; the client renders that as "empty". */
	ASSERT_NEQ(test_command_ok(ctx, "GET_ATTRIBUTE algorithm.1"),
		   (gpg_error_t) 0);

	/* The baked-presentation "slots" summary is gone from the daemon. */
	ASSERT_NEQ(test_command_ok(ctx, "GET_ATTRIBUTE slots"), (gpg_error_t) 0);

	test_server_stop(ctx, pid);
	cleanup();
}

TEST(test_get_attribute_keygrip_fpr_time)
{
	setup();
	create_test_token("gk", "1234", "nistp256");

	/* Replace slot 0's fake pubkey with a real key so keygrip is valid,
	   and stamp fpr/time so those attributes have something to return. */
	char tpath[512], mpath[560];
	tokenstore_token_path(store, "gk", tpath, sizeof(tpath));
	snprintf(mpath, sizeof(mpath), "%s/metadata", tpath);
	unsigned char mk[KEYWRAP_MK_LEN];
	ASSERT_EQ(keywrap_open(tpath, "1234", 4, mk), 0);
	unsigned char *key = NULL;
	size_t key_len = 0;
	ASSERT_EQ(crypto_ec_keygen("nistp256", &key, &key_len), 0);
	char algo[64] = { 0 };
	ASSERT_EQ(store_key_into_slot(store, "gk", 0, key, key_len, mk, NULL, algo),
		  (gpg_error_t) 0);
	secure_free(key, key_len);
	token_meta_t m0 = { 0 };
	ASSERT_EQ(meta_read(mpath, &m0), 0);
	m0.key_fpr_hex[0] = strdup("DEADBEEF");
	m0.key_time[0] = strdup("1700000000");
	ASSERT_EQ(meta_write(mpath, &m0), 0);
	meta_free(&m0);

	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);
	ASSERT_EQ(test_command_ok(ctx, "OPEN_SESSION gk"), (gpg_error_t) 0);

	char *data = NULL;
	size_t dlen = 0;
	/* keygrip.0: 40 uppercase hex chars */
	ASSERT_EQ(test_command(ctx, "GET_ATTRIBUTE keygrip.0", &data, &dlen),
		  (gpg_error_t) 0);
	ASSERT_EQ(dlen, (size_t)40);
	free(data);

	/* fpr.0 and time.0 round-trip the stored values */
	data = NULL; dlen = 0;
	ASSERT_EQ(test_command(ctx, "GET_ATTRIBUTE fpr.0", &data, &dlen),
		  (gpg_error_t) 0);
	ASSERT(dlen == 8 && memcmp(data, "DEADBEEF", 8) == 0);
	free(data);

	data = NULL; dlen = 0;
	ASSERT_EQ(test_command(ctx, "GET_ATTRIBUTE time.0", &data, &dlen),
		  (gpg_error_t) 0);
	ASSERT(dlen == 10 && memcmp(data, "1700000000", 10) == 0);
	free(data);

	/* An empty slot reports NOT_FOUND for keygrip */
	ASSERT_NEQ(test_command_ok(ctx, "GET_ATTRIBUTE keygrip.1"), (gpg_error_t) 0);

	test_server_stop(ctx, pid);
	cleanup();
}

TEST(test_set_attribute_fpr_time)
{
	setup();
	create_test_token("sa", "1234", "rsa2048");
	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);
	ASSERT_EQ(test_command_ok(ctx, "OPEN_SESSION sa"), (gpg_error_t) 0);

	ASSERT_EQ(test_command_ok(ctx, "SET_ATTRIBUTE 0 KEY-FPR CAFE1234"),
		  (gpg_error_t) 0);
	ASSERT_EQ(test_command_ok(ctx, "SET_ATTRIBUTE 0 KEY-TIME 1699999999"),
		  (gpg_error_t) 0);

	char *data = NULL;
	size_t dlen = 0;
	ASSERT_EQ(test_command(ctx, "GET_ATTRIBUTE fpr.0", &data, &dlen),
		  (gpg_error_t) 0);
	ASSERT(dlen == 8 && memcmp(data, "CAFE1234", 8) == 0);
	free(data);
	data = NULL; dlen = 0;
	ASSERT_EQ(test_command(ctx, "GET_ATTRIBUTE time.0", &data, &dlen),
		  (gpg_error_t) 0);
	ASSERT(dlen == 10 && memcmp(data, "1699999999", 10) == 0);
	free(data);

	/* Unknown attribute name is rejected. */
	ASSERT_NEQ(test_command_ok(ctx, "SET_ATTRIBUTE 0 BOGUS x"),
		   (gpg_error_t) 0);

	test_server_stop(ctx, pid);
	cleanup();
}

/*
 * Provision a real EC key into slot 0 of an already-created token, so its
 * LIST_KEYS entry has a valid keygrip (create_test_token's default "aabb"
 * pubkey does not compute one).
 */
static void
provision_real_key(const char *label, const char *pin)
{
	char tpath[512];
	tokenstore_token_path(store, label, tpath, sizeof(tpath));
	unsigned char mk[KEYWRAP_MK_LEN];
	ASSERT_EQ(keywrap_open(tpath, pin, strlen(pin), mk), 0);
	unsigned char *key = NULL;
	size_t key_len = 0;
	ASSERT_EQ(crypto_ec_keygen("nistp256", &key, &key_len), 0);
	char algo[64] = { 0 };
	ASSERT_EQ(store_key_into_slot(store, label, 0, key, key_len, mk, NULL,
				      algo), (gpg_error_t) 0);
	secure_free(key, key_len);
}

TEST(test_disconnect_before_connect)
{
	setup();
	create_test_token("test1", "1234", "nistp256");
	provision_real_key("test1", "1234");

	/* Disconnect BEFORE starting the daemon connection */
	char tpath[512];
	tokenstore_token_path(store, "test1", tpath, sizeof(tpath));
	token_state_t dst = { .pin_retries = 3, .disconnected = 1 };
	state_write(tpath, &dst);

	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);

	/* LIST_KEYS on a fresh connection with a pre-disconnected token: the
	   token's key must not appear. */
	char *status = NULL;
	ASSERT_EQ(test_command_status(ctx, "LIST_KEYS", &status),
		  (gpg_error_t) 0);
	ASSERT(status[0] == '\0' || strstr(status, "test1") == NULL);
	free(status);

	/* LIST_TOKENS still shows it, marked disconnected. */
	status = NULL;
	ASSERT_EQ(test_command_status(ctx, "LIST_TOKENS", &status),
		  (gpg_error_t) 0);
	ASSERT_NOT_NULL(status);
	ASSERT(strstr(status, "test1") != NULL);
	ASSERT(strstr(status, "disconnected") != NULL);
	free(status);

	test_server_stop(ctx, pid);
	cleanup();
}

TEST(test_disconnect_hides_from_list_keys)
{
	setup();
	create_test_token("d1", "1234", "nistp256");
	char tpath[512];
	tokenstore_token_path(store, "d1", tpath, sizeof(tpath));
	unsigned char mk[KEYWRAP_MK_LEN];
	ASSERT_EQ(keywrap_open(tpath, "1234", 4, mk), 0);
	unsigned char *key = NULL;
	size_t key_len = 0;
	ASSERT_EQ(crypto_ec_keygen("nistp256", &key, &key_len), 0);
	char algo[64] = { 0 };
	ASSERT_EQ(store_key_into_slot(store, "d1", 0, key, key_len, mk, NULL, algo),
		  (gpg_error_t) 0);
	secure_free(key, key_len);

	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);

	char *status = NULL;
	ASSERT_EQ(test_command_status(ctx, "LIST_KEYS", &status), (gpg_error_t) 0);
	ASSERT(strstr(status, "d1") != NULL);
	free(status);

	token_state_t st = { .pin_retries = 3, .disconnected = 1 };
	state_write(tpath, &st);

	status = NULL;
	ASSERT_EQ(test_command_status(ctx, "LIST_KEYS", &status), (gpg_error_t) 0);
	ASSERT(status == NULL || strstr(status, "d1") == NULL);
	free(status);

	/* LIST_TOKENS still shows it, marked disconnected. */
	status = NULL;
	ASSERT_EQ(test_command_status(ctx, "LIST_TOKENS", &status), (gpg_error_t) 0);
	ASSERT(strstr(status, "d1") != NULL);
	ASSERT(strstr(status, "disconnected") != NULL);
	free(status);

	test_server_stop(ctx, pid);
	cleanup();
}

TEST(test_disconnect_with_two_tokens)
{
	setup();
	create_test_token("tok1", "1234", "nistp256");
	create_test_token("tok2", "5678", "nistp256");
	provision_real_key("tok1", "1234");
	provision_real_key("tok2", "5678");

	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);

	/* Both tokens' keys are visible before any disconnect. */
	char *status = NULL;
	ASSERT_EQ(test_command_status(ctx, "LIST_KEYS", &status), (gpg_error_t) 0);
	ASSERT(strstr(status, "tok1") != NULL);
	ASSERT(strstr(status, "tok2") != NULL);
	free(status);

	/* Disconnect both tokens */
	char tp1[512], tp2[512];
	tokenstore_token_path(store, "tok1", tp1, sizeof(tp1));
	tokenstore_token_path(store, "tok2", tp2, sizeof(tp2));
	token_state_t dst = { .pin_retries = 3, .disconnected = 1 };
	state_write(tp1, &dst);
	state_write(tp2, &dst);

	/* LIST_KEYS must show neither -- all tokens disconnected */
	status = NULL;
	ASSERT_EQ(test_command_status(ctx, "LIST_KEYS", &status), (gpg_error_t) 0);
	ASSERT(strstr(status, "tok1") == NULL);
	ASSERT(strstr(status, "tok2") == NULL);
	free(status);

	/* Reconnect tok2 */
	dst.disconnected = 0;
	state_write(tp2, &dst);

	/* LIST_KEYS should show tok2's key again, but not tok1's */
	status = NULL;
	ASSERT_EQ(test_command_status(ctx, "LIST_KEYS", &status), (gpg_error_t) 0);
	ASSERT(strstr(status, "tok2") != NULL);
	ASSERT(strstr(status, "tok1") == NULL);
	free(status);

	test_server_stop(ctx, pid);
	cleanup();
}

TEST(test_disconnect_hides_from_list_tokens)
{
	setup();
	create_test_token("alpha", "1234", "rsa2048");
	create_test_token("beta", "1234", "nistp256");
	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);

	/* Disconnect alpha */
	char tpath[512];
	tokenstore_token_path(store, "alpha", tpath, sizeof(tpath));
	token_state_t dst = { .pin_retries = 3, .disconnected = 1 };
	state_write(tpath, &dst);

	char *status = NULL;
	ASSERT_EQ(test_command_status(ctx, "LIST_TOKENS", &status),
		  (gpg_error_t) 0);
	ASSERT_NOT_NULL(status);
	ASSERT(strstr(status, "alpha disconnected") != NULL);
	ASSERT(strstr(status, "beta connected") != NULL);
	free(status);

	test_server_stop(ctx, pid);
	cleanup();
}

TEST(test_disconnect_command)
{
	setup();
	create_test_token("mytoken", "1234", "nistp256");
	provision_real_key("mytoken", "1234");

	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);

	/* LIST_KEYS shows the token's key before disconnect */
	char *status = NULL;
	ASSERT_EQ(test_command_status(ctx, "LIST_KEYS", &status), (gpg_error_t) 0);
	ASSERT(strstr(status, "mytoken") != NULL);
	free(status);

	/* DISCONNECT_TOKEN via the same connection */
	ASSERT_EQ(test_command_ok(ctx, "DISCONNECT_TOKEN mytoken"),
		  (gpg_error_t) 0);

	/* LIST_KEYS must now hide it */
	status = NULL;
	ASSERT_EQ(test_command_status(ctx, "LIST_KEYS", &status), (gpg_error_t) 0);
	ASSERT(status[0] == '\0' || strstr(status, "mytoken") == NULL);
	free(status);

	/* CONNECT_TOKEN brings it back */
	ASSERT_EQ(test_command_ok(ctx, "CONNECT_TOKEN mytoken"),
		  (gpg_error_t) 0);
	status = NULL;
	ASSERT_EQ(test_command_status(ctx, "LIST_KEYS", &status), (gpg_error_t) 0);
	ASSERT(strstr(status, "mytoken") != NULL);
	free(status);

	test_server_stop(ctx, pid);
	cleanup();
}

TEST(test_import_unsupported_curve_rejected)
{
	setup();
	create_test_token("edtok", "1234", "rsa2048");

	char tpath[512];
	tokenstore_token_path(store, "edtok", tpath, sizeof(tpath));
	unsigned char mk[KEYWRAP_MK_LEN];
	ASSERT_EQ(keywrap_open(tpath, "1234", 4, mk), 0);

	/* A well-formed key on a curve reliquary does not support (Ed448).
	   It must be rejected, not silently mislabeled and stored as another
	   algorithm. */
	unsigned char *key = NULL;
	size_t key_len = 0;
	ASSERT_EQ(crypto_ec_keygen("Ed448", &key, &key_len), 0);

	char algo[64] = { 0 };
	gpg_error_t err = store_key_into_slot(store, "edtok", 2, key, key_len,
					      mk, NULL, algo);
	ASSERT_EQ(gpg_err_code(err), GPG_ERR_NOT_SUPPORTED);

	secure_free(key, key_len);
	cleanup();
}

/*
 * GENKEY must populate the slot's allowed_mechs metadata with the
 * mechpolicy default set for (algo, slot); an optional trailing additions
 * argument is merged in on top of the default. Purely additive -- nothing
 * enforces allowed_mechs yet.
 */
TEST(test_genkey_sets_allowed_mechs)
{
	setup();
	create_test_token("mechtok", "1234", "rsa2048");
	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);

	ASSERT_EQ(test_command_ok(ctx, "OPEN_SESSION mechtok"), (gpg_error_t) 0);
	ASSERT_EQ(test_command_ok(ctx, "LOGIN 1234"), (gpg_error_t) 0);

	char mpath[768];
	{
		char tpath[512];
		tokenstore_token_path(store, "mechtok", tpath, sizeof(tpath));
		snprintf(mpath, sizeof(mpath), "%s/metadata", tpath);
	}

	/* No additions: the encrypt slot gets exactly the default set. */
	ASSERT_EQ(test_command_ok(ctx, "GENKEY 1 rsa2048"), (gpg_error_t) 0);

	token_meta_t m = { 0 };
	ASSERT_EQ(meta_read(mpath, &m), 0);
	ASSERT_STR_EQ(m.allowed_mechs[RELIQUARY_SLOT_ENCRYPT],
		      "decrypt.rsa-pkcs1,decrypt.rsa-oaep");
	meta_free(&m);

	/* An explicit addition is appended to the default set. */
	ASSERT_EQ(test_command_ok(ctx, "GENKEY 1 rsa2048 decrypt.rsa-raw"),
		  (gpg_error_t) 0);

	memset(&m, 0, sizeof(m));
	ASSERT_EQ(meta_read(mpath, &m), 0);
	ASSERT_STR_EQ(m.allowed_mechs[RELIQUARY_SLOT_ENCRYPT],
		      "decrypt.rsa-pkcs1,decrypt.rsa-oaep,decrypt.rsa-raw");
	meta_free(&m);

	test_server_stop(ctx, pid);
	cleanup();
}

TEST(test_tokenstore_valid_label)
{
	/* Ordinary labels are accepted. */
	ASSERT_EQ(tokenstore_valid_label("work"), 1);
	ASSERT_EQ(tokenstore_valid_label("my.token_1-2"), 1);
	/* Traversal and path separators are rejected. */
	ASSERT_EQ(tokenstore_valid_label(".."), 0);
	ASSERT_EQ(tokenstore_valid_label("."), 0);
	ASSERT_EQ(tokenstore_valid_label("../evil"), 0);
	ASSERT_EQ(tokenstore_valid_label("a/b"), 0);
	/* Empty and whitespace are rejected. */
	ASSERT_EQ(tokenstore_valid_label(""), 0);
	ASSERT_EQ(tokenstore_valid_label("a b"), 0);
}

TEST(test_create_token_rejects_traversal_label)
{
	setup();

	/* store/../pwned resolves outside the store. Pre-clean any escape
	   target a prior failing run may have left, so the post-check below
	   actually proves this run created nothing. */
	char rmcmd[700], escaped[700];
	snprintf(rmcmd, sizeof(rmcmd), "rm -rf %s/../pwned", store);
	snprintf(escaped, sizeof(escaped), "%s/../pwned", store);
	ASSERT_EQ(system(rmcmd), 0);

	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);

	/* Initialize the store over the wire so the admin PIN is exactly
	   "adminpin" in the format verify_admin_pin() expects. */
	ASSERT_EQ(test_command_ok(ctx, "INIT_STORE adminpin"), (gpg_error_t) 0);

	/* Positive control: a normal CREATE_TOKEN with the same admin PIN
	   succeeds, so the rejection below can only be about the label. */
	ASSERT_EQ(test_command_ok(ctx, "CREATE_TOKEN good 1234 adminpin"),
		  (gpg_error_t) 0);

	/* A label that would escape the per-uid store must be refused. */
	ASSERT_NEQ(test_command_ok(ctx, "CREATE_TOKEN ../pwned 1234 adminpin"),
		   (gpg_error_t) 0);

	test_server_stop(ctx, pid);

	/* ...and nothing may have been created outside the store. */
	struct stat stx;
	ASSERT_NEQ(stat(escaped, &stx), 0);

	ASSERT_EQ(system(rmcmd), 0);
	cleanup();
}

TEST(test_list_tokens_status_has_serial)
{
	setup();
	create_test_token("alpha", "1234", "rsa2048");
	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);

	char *status = NULL;
	ASSERT_EQ(test_command_status(ctx, "LIST_TOKENS", &status),
		  (gpg_error_t) 0);
	ASSERT_NOT_NULL(status);
	/* Expect: "TOKEN D276000124010300FFFF000000010000 alpha connected" */
	ASSERT(strstr(status, "TOKEN ") != NULL);
	ASSERT(strstr(status, "D276000124010300FFFF") != NULL);
	ASSERT(strstr(status, "alpha") != NULL);
	ASSERT(strstr(status, "connected") != NULL);
	free(status);

	test_server_stop(ctx, pid);
	cleanup();
}

TEST(test_list_keys)
{
	setup();
	/* Two tokens; give each a real key in slot 0 so keygrips are valid. */
	create_test_token("ka", "1234", "nistp256");
	create_test_token("kb", "1234", "nistp256");
	for (int t = 0; t < 2; t++) {
		const char *label = t == 0 ? "ka" : "kb";
		char tpath[512];
		tokenstore_token_path(store, label, tpath, sizeof(tpath));
		unsigned char mk[KEYWRAP_MK_LEN];
		ASSERT_EQ(keywrap_open(tpath, "1234", 4, mk), 0);
		unsigned char *key = NULL;
		size_t key_len = 0;
		ASSERT_EQ(crypto_ec_keygen("nistp256", &key, &key_len), 0);
		char algo[64] = { 0 };
		ASSERT_EQ(store_key_into_slot(store, label, 0, key, key_len, mk,
					      NULL, algo), (gpg_error_t) 0);
		secure_free(key, key_len);
	}

	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);
	char *status = NULL;
	ASSERT_EQ(test_command_status(ctx, "LIST_KEYS", &status), (gpg_error_t) 0);
	ASSERT_NOT_NULL(status);
	/* Both tokens' slot-0 keys are listed, tagged with their label and slot 0. */
	ASSERT(strstr(status, "ka") != NULL);
	ASSERT(strstr(status, "kb") != NULL);
	/* Empty fpr/time render as "-" (create_test_token stores neither). */
	ASSERT(strstr(status, " - - ") != NULL);
	free(status);

	/* Disconnecting kb hides its keys from LIST_KEYS. */
	char kbpath[512];
	tokenstore_token_path(store, "kb", kbpath, sizeof(kbpath));
	token_state_t st = { .pin_retries = 3, .disconnected = 1 };
	state_write(kbpath, &st);
	status = NULL;
	ASSERT_EQ(test_command_status(ctx, "LIST_KEYS", &status), (gpg_error_t) 0);
	ASSERT(strstr(status, "ka") != NULL);
	ASSERT(strstr(status, "kb") == NULL);
	free(status);

	test_server_stop(ctx, pid);
	cleanup();
}

struct import_inq_fixture {
	assuan_context_t ctx;
	const unsigned char *key;
	size_t key_len;
	const char *pin;	/* NULL means "1234" */
};

static gpg_error_t
import_inq_cb(void *opaque, const char *name)
{
	struct import_inq_fixture *f = opaque;
	if (strncmp(name, "NEEDPIN", 7) == 0) {
		const char *pin = f->pin ? f->pin : "1234";
		return assuan_send_data(f->ctx, pin, strlen(pin));
	}
	/* KEYDATA */
	return assuan_send_data(f->ctx, f->key, f->key_len);
}

TEST(test_import_slot_needpin_on_demand)
{
	setup();
	create_test_token("imp", "1234", "rsa2048");

	unsigned char *key = NULL;
	size_t key_len = 0;
	ASSERT_EQ(crypto_ec_keygen("nistp256", &key, &key_len), 0);

	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);

	/* No OPEN_SESSION, no LOGIN: ensure_logged_in auto-opens the sole token
	   and prompts NEEDPIN, which our callback answers with the token PIN. */
	struct import_inq_fixture f = { ctx, key, key_len, NULL };
	gpg_error_t err = assuan_transact(ctx, "IMPORT_SLOT 2", NULL, NULL,
					  import_inq_cb, &f, NULL, NULL);
	ASSERT_EQ(err, (gpg_error_t) 0);
	secure_free(key, key_len);

	/* Slot 2 (auth) is now populated: a real EC pubkey is stored. */
	char *data = NULL;
	size_t dlen = 0;
	ASSERT_EQ(test_command(ctx, "GET_ATTRIBUTE algorithm.2", &data, &dlen),
		  (gpg_error_t) 0);
	ASSERT(dlen >= 5 && memcmp(data, "nistp", 5) == 0);
	free(data);

	test_server_stop(ctx, pid);
	cleanup();
}

/*
 * Regression for the parse-after-inquiry buffer clobber: with a LONG PIN
 * (long enough that the NEEDPIN inquiry reply overwrites the tail of
 * libassuan's inbound line buffer, which is where the "2" slot argument of
 * "IMPORT_SLOT 2" lives), IMPORT_SLOT must still parse slot 2 out of `line`
 * BEFORE ensure_logged_in()'s NEEDPIN inquiry runs. The short-PIN "1234"
 * used by test_import_slot_needpin_on_demand above does not reach far
 * enough into the buffer to reproduce this.
 */
TEST(test_import_slot_needpin_long_pin)
{
	setup();
	create_test_token("imp2", "longpassphrase12", "rsa2048");

	unsigned char *key = NULL;
	size_t key_len = 0;
	ASSERT_EQ(crypto_ec_keygen("nistp256", &key, &key_len), 0);

	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);

	/* No OPEN_SESSION, no LOGIN: ensure_logged_in auto-opens the sole token
	   and prompts NEEDPIN, which our callback answers with the long PIN. */
	struct import_inq_fixture f =
	    { ctx, key, key_len, "longpassphrase12" };
	gpg_error_t err = assuan_transact(ctx, "IMPORT_SLOT 2", NULL, NULL,
					  import_inq_cb, &f, NULL, NULL);
	ASSERT_EQ(err, (gpg_error_t) 0);
	secure_free(key, key_len);

	/* Slot 2 (auth) is populated with the real EC key we imported. */
	char *data = NULL;
	size_t dlen = 0;
	ASSERT_EQ(test_command(ctx, "GET_ATTRIBUTE algorithm.2", &data, &dlen),
		  (gpg_error_t) 0);
	ASSERT(dlen >= 5 && memcmp(data, "nistp", 5) == 0);
	free(data);

	/* Slot 0 (sign) is untouched by the import: a clobbered slot_str would
	   parse as slot 0 (atoi() on garbage yields 0) and store the EC key
	   there instead, stomping create_test_token's rsa2048 sign key. */
	data = NULL;
	dlen = 0;
	ASSERT_EQ(test_command(ctx, "GET_ATTRIBUTE algorithm.0", &data, &dlen),
		  (gpg_error_t) 0);
	ASSERT(dlen >= 7 && memcmp(data, "rsa2048", 7) == 0);
	free(data);

	test_server_stop(ctx, pid);
	cleanup();
}

/*
 * Inquiry-clobber regression matrix (#1).
 *
 * Every command that BOTH parses arguments out of `line` AND issues an
 * assuan_inquire() shares a hazard: libassuan reuses its inbound line buffer
 * for the inquiry reply, so any argument not copied out of `line` BEFORE the
 * inquiry is read back corrupted.  This bit IMPORT_SLOT once already (the
 * NEEDPIN reply overwrote the slot argument for a realistic-length PIN).  The
 * tests below drive SIGN/DECRYPT/DERIVE and IMPORT_SLOT's additions with a PIN
 * long enough to overwrite the argument region of the inbound buffer during
 * ensure_logged_in()'s NEEDPIN, and assert the pre-inquiry-captured arguments
 * were honored.  They pass on the current (correct) code and would fail if a
 * handler were reordered to parse an argument after the inquiry.
 */

struct crypto_inq_fixture {
	assuan_context_t ctx;
	const char *pin;		/* answer to NEEDPIN */
	const unsigned char *data;	/* answer to VALUE/CIPHERTEXT/PEERKEY */
	size_t data_len;
};

struct byte_sink {
	size_t len;
};

/*
 * IMPORT_SLOT's additions token is the other value parsed alongside the slot;
 * it must survive the same NEEDPIN clobber. Import with a long PIN and an
 * additions token, then confirm the slot's allowed_mechs picked it up.
 */
TEST(test_import_slot_clobber_additions)
{
	setup();
	create_test_token("impa", "longpassphrase12", "rsa2048");

	unsigned char *key = NULL;
	size_t key_len = 0;
	ASSERT_EQ(crypto_ec_keygen("nistp256", &key, &key_len), 0);

	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);

	struct import_inq_fixture f =
	    { ctx, key, key_len, "longpassphrase12" };
	gpg_error_t err = assuan_transact(ctx, "IMPORT_SLOT 2 decrypt.rsa-raw",
					  NULL, NULL, import_inq_cb, &f,
					  NULL, NULL);
	ASSERT_EQ(err, (gpg_error_t) 0);
	secure_free(key, key_len);

	char tpath[512], mpath[768];
	tokenstore_token_path(store, "impa", tpath, sizeof(tpath));
	snprintf(mpath, sizeof(mpath), "%s/metadata", tpath);
	token_meta_t m = { 0 };
	ASSERT_EQ(meta_read(mpath, &m), 0);
	ASSERT_NOT_NULL(m.allowed_mechs[2]);
	ASSERT(strstr(m.allowed_mechs[2], "decrypt.rsa-raw") != NULL);
	meta_free(&m);

	test_server_stop(ctx, pid);
	cleanup();
}

/*
 * Never-announced raw RSA (#3).  decrypt.rsa-raw is usable per slot when a
 * slot explicitly opts in, but GET_MECHANISM_LIST must never advertise it --
 * so a client cannot discover raw RSA from the announced mechanism list.
 */
TEST(test_mechanism_list_never_announces_raw)
{
	setup();
	create_test_token("raw", "1234", "rsa2048");

	assuan_context_t ctx;
	pid_t pid;
	ASSERT_EQ(test_server_start(store, &ctx, &pid), 0);
	ASSERT_EQ(test_command_ok(ctx, "OPEN_SESSION raw"), (gpg_error_t) 0);
	ASSERT_EQ(test_command_ok(ctx, "LOGIN 1234"), (gpg_error_t) 0);

	/* Opt slot 1 into raw RSA. */
	ASSERT_EQ(test_command_ok(ctx, "GENKEY 1 rsa2048 decrypt.rsa-raw"),
		  (gpg_error_t) 0);

	/* Control: the slot really did record decrypt.rsa-raw in its allowed set. */
	char tpath[512], mpath[768];
	tokenstore_token_path(store, "raw", tpath, sizeof(tpath));
	snprintf(mpath, sizeof(mpath), "%s/metadata", tpath);
	token_meta_t m = { 0 };
	ASSERT_EQ(meta_read(mpath, &m), 0);
	ASSERT_NOT_NULL(m.allowed_mechs[RELIQUARY_SLOT_ENCRYPT]);
	ASSERT(strstr(m.allowed_mechs[RELIQUARY_SLOT_ENCRYPT], "decrypt.rsa-raw")
	       != NULL);
	meta_free(&m);

	/* GET_MECHANISM_LIST still omits it. */
	char *data = NULL;
	size_t dlen = 0;
	ASSERT_EQ(test_command(ctx, "GET_MECHANISM_LIST", &data, &dlen),
		  (gpg_error_t) 0);
	char *tmp = malloc(dlen + 1);
	memcpy(tmp, data, dlen);
	tmp[dlen] = '\0';
	ASSERT(strstr(tmp, "decrypt.rsa-raw") == NULL);
	free(tmp);
	free(data);

	test_server_stop(ctx, pid);
	cleanup();
}

TEST(test_mechpolicy_advertised_list)
{
	char buf[256];
	mechpolicy_advertised(buf, sizeof(buf));
	/* Advertised set: 7 tokens, decrypt.rsa-raw excluded. */
	ASSERT_STR_EQ(buf,
		"sign.rsa-pkcs1\n"
		"sign.rsa-pss\n"
		"sign.ecdsa\n"
		"sign.eddsa\n"
		"decrypt.rsa-pkcs1\n"
		"decrypt.rsa-oaep\n"
		"derive.ecdh");
	/* Unadvertised raw RSA must not appear. */
	ASSERT_EQ((int)(strstr(buf, "rsa-raw") == NULL), 1);
}

TEST_MAIN_BEGIN("test_daemon")
    ASSERT_EQ(crypto_init(), 0);
RUN(test_connect_and_nop);
RUN(test_unknown_command);
RUN(test_open_session);
RUN(test_open_session_nonexistent);
RUN(test_login_and_logout);
RUN(test_login_wrong_pin);
RUN(test_login_empty_needpin);
RUN(test_list_tokens);
RUN(test_list_tokens_status_has_serial);
RUN(test_list_keys);
RUN(test_get_mechanism_list);
RUN(test_get_attribute_slots_removed);
RUN(test_get_attribute_keygrip_fpr_time);
RUN(test_set_attribute_fpr_time);
RUN(test_disconnect_before_connect);
RUN(test_disconnect_hides_from_list_keys);
RUN(test_disconnect_with_two_tokens);
RUN(test_disconnect_hides_from_list_tokens);
RUN(test_disconnect_command);
RUN(test_import_unsupported_curve_rejected);
RUN(test_genkey_sets_allowed_mechs);
RUN(test_tokenstore_valid_label);
RUN(test_create_token_rejects_traversal_label);
RUN(test_import_slot_needpin_on_demand);
RUN(test_import_slot_needpin_long_pin);
RUN(test_import_slot_clobber_additions);
RUN(test_mechanism_list_never_announces_raw);
RUN(test_mechpolicy_advertised_list);
TEST_MAIN_END
