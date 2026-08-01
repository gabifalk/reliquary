/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "testutil.h"
#include "client.h"
#include "crypto_rsa.h"
#include "hex.h"
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <gcrypt.h>

static char store_dir[] = "/tmp/test_reliqd_store_XXXXXX";
static char xdg_dir[] = "/tmp/test_reliqd_xdg_XXXXXX";
static char socket_path[512];
static char daemon_path[512];
static pid_t daemon_pid = -1;

static void
cleanup(void)
{
	if (daemon_pid > 0) {
		/* Kill entire process group (daemon + forked children) */
		kill(-daemon_pid, SIGTERM);
		waitpid(daemon_pid, NULL, 0);
		daemon_pid = -1;
	}
	char cmd[512];
	snprintf(cmd, sizeof(cmd), "rm -rf '%s' '%s'", store_dir, xdg_dir);
	ASSERT_EQ(system(cmd), 0);
}

static int
wait_for_socket(const char *path, int timeout_ms)
{
	struct stat st;
	for (int elapsed = 0; elapsed < timeout_ms; elapsed += 10) {
		if (stat(path, &st) == 0)
			return 0;
		usleep(10000);
	}
	return -1;
}

static void
start_daemon(void)
{
	ASSERT_NOT_NULL(mkdtemp(store_dir));
	ASSERT_NOT_NULL(mkdtemp(xdg_dir));

	snprintf(socket_path, sizeof(socket_path),
		 "%s/reliquary/socket", xdg_dir);

	/* Daemon path is passed via env from meson test definition */
	const char *dpath = getenv("RELIQUARYD_PATH");
	if (!dpath)
		dpath = "src/daemon/reliquaryd";
	snprintf(daemon_path, sizeof(daemon_path), "%s", dpath);

	daemon_pid = fork();
	ASSERT(daemon_pid >= 0);

	if (daemon_pid == 0) {
		/* New process group so we can kill daemon + all forked children */
		setpgid(0, 0);
		setenv("XDG_RUNTIME_DIR", xdg_dir, 1);
		execl(daemon_path, "reliquaryd", "--store", store_dir, NULL);
		perror("execl");
		_exit(127);
	}
	setpgid(daemon_pid, daemon_pid);

	/* Parent: wait for the socket to appear */
	if (wait_for_socket(socket_path, 5000) != 0) {
		fprintf(stderr, "Daemon socket did not appear at %s\n",
			socket_path);
		cleanup();
		exit(1);
	}
}

static assuan_context_t
connect_client(void)
{
	setenv("RELIQUARY_SOCKET", socket_path, 1);
	assuan_context_t ctx;
	ASSERT_EQ(client_connect(&ctx), 0);
	return ctx;
}

/* Helper: send command, collect data response */
static char *
cmd_data(assuan_context_t ctx, const char *cmd, size_t * out_len)
{
	char *data = NULL;
	size_t len = 0;
	gpg_error_t err = client_command(ctx, cmd, &data, &len);
	ASSERT_EQ(err, (gpg_error_t) 0);
	if (out_len)
		*out_len = len;
	return data;
}

/* Helper: SIGN a hex-described payload via the wire path (INQUIRE VALUE),
   returning the raw signature. The payload is still spelled as hex in the
   callers below for readability, but travels out-of-band as raw binary --
   not on the SIGN command line -- mirroring cmd_sign / impl_Sign. */
static unsigned char *
sign_wire(assuan_context_t ctx, const char *slot_and_mech,
	  const char *hex_data, size_t * out_len)
{
	unsigned char data[256];
	size_t data_len = 0;
	ASSERT_EQ(hex_decode(hex_data, data, sizeof(data), &data_len), 0);

	unsigned char *sig = NULL;
	size_t sig_len = 0;
	gpg_error_t err = client_command_data_reply(ctx, slot_and_mech,
						    data, data_len,
						    &sig, &sig_len);
	ASSERT_EQ(err, (gpg_error_t) 0);
	if (out_len)
		*out_len = sig_len;
	return sig;
}

/* Helper: null-terminate data for string searches */
static char *
cmd_data_str(assuan_context_t ctx, const char *cmd)
{
	size_t len = 0;
	char *data = cmd_data(ctx, cmd, &len);
	char *str = malloc(len + 1);
	ASSERT_NOT_NULL(str);
	memcpy(str, data, len);
	str[len] = '\0';
	free(data);
	return str;
}

static gpg_error_t
_integ_status_cb(void *opaque, const char *line)
{
	char *buf = opaque;
	strncat(buf, line, 2048 - strlen(buf) - 2);
	strncat(buf, "\n", 2048 - strlen(buf) - 1);
	return 0;
}

static char *
cmd_status_str(assuan_context_t ctx, const char *cmd)
{
	char *buf = calloc(1, 2048);
	client_command_status(ctx, cmd, _integ_status_cb, buf);
	return buf;
}

/* Load the committed rsa4096 fixture private key (canonical gcrypt
   S-expression, see tests/gen_fixture_rsa4096_key.sh). Generating a fresh
   rsa4096 key at test time is too slow, so this is generated once, offline,
   and committed under tests/data/. Returns malloc'd bytes; caller frees. */
static unsigned char *
load_fixture_rsa4096(size_t * out_len)
{
	const char *path = getenv("FIXTURE_RSA4096_PATH");
	if (!path)
		path = "data/fixture_rsa4096.key";

	FILE *f = fopen(path, "rb");
	ASSERT_NOT_NULL(f);
	ASSERT_EQ(fseek(f, 0, SEEK_END), 0);
	long sz = ftell(f);
	ASSERT(sz > 0);
	ASSERT_EQ(fseek(f, 0, SEEK_SET), 0);

	unsigned char *buf = malloc((size_t)sz);
	ASSERT_NOT_NULL(buf);
	ASSERT_EQ(fread(buf, 1, (size_t)sz, f), (size_t)sz);
	fclose(f);

	*out_len = (size_t)sz;
	return buf;
}

/* ---- Tests ---- */

TEST(test_create_token_and_list)
{
	assuan_context_t ctx = connect_client();

	ASSERT_EQ(client_command_ok(ctx, "CREATE_TOKEN testkey1 1234 adminpin"),
		  (gpg_error_t) 0);

	char *list = cmd_status_str(ctx, "LIST_TOKENS");
	ASSERT(strstr(list, "testkey1") != NULL);
	free(list);

	client_disconnect(ctx);
}

TEST(test_login_sign_rsa)
{
	assuan_context_t ctx = connect_client();

	ASSERT_EQ(client_command_ok(ctx, "CREATE_TOKEN rsakey secret adminpin"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "OPEN_SESSION rsakey"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "LOGIN secret"), (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "GENKEY 0 rsa2048"),
		  (gpg_error_t) 0);

	/* Sign a 32-byte SHA-256 hash (hex-encoded = 64 chars) */
	size_t sig_len = 0;
	unsigned char *sig = sign_wire(ctx, "SIGN 0 sign.rsa-pkcs1",
				       "3031300d060960864801650304020105000420aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				       &sig_len);
	ASSERT(sig_len > 0);
	free(sig);

	ASSERT_EQ(client_command_ok(ctx, "LOGOUT"), (gpg_error_t) 0);
	client_disconnect(ctx);
}

TEST(test_genkey_rsa1024_rejected)
{
	assuan_context_t ctx = connect_client();

	ASSERT_EQ(client_command_ok
		  (ctx, "CREATE_TOKEN rsa1024key secret adminpin"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "OPEN_SESSION rsa1024key"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "LOGIN secret"), (gpg_error_t) 0);

	/* 1024-bit RSA is below the advertised 2048-bit minimum. */
	ASSERT(client_command_ok(ctx, "GENKEY 0 rsa1024") != (gpg_error_t) 0);

	ASSERT_EQ(client_command_ok(ctx, "LOGOUT"), (gpg_error_t) 0);
	client_disconnect(ctx);
}

TEST(test_login_sign_ec)
{
	assuan_context_t ctx = connect_client();

	ASSERT_EQ(client_command_ok(ctx, "CREATE_TOKEN eckey mypin adminpin"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "OPEN_SESSION eckey"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "LOGIN mypin"), (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "GENKEY 0 nistp256"),
		  (gpg_error_t) 0);

	size_t sig_len = 0;
	unsigned char *sig = sign_wire(ctx, "SIGN 0 sign.ecdsa",
				       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				       &sig_len);
	ASSERT(sig_len > 0);
	free(sig);

	ASSERT_EQ(client_command_ok(ctx, "LOGOUT"), (gpg_error_t) 0);
	client_disconnect(ctx);
}

TEST(test_login_sign_ed25519)
{
	assuan_context_t ctx = connect_client();

	ASSERT_EQ(client_command_ok(ctx, "CREATE_TOKEN edkey edpin adminpin"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "OPEN_SESSION edkey"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "LOGIN edpin"), (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "GENKEY 0 ed25519"),
		  (gpg_error_t) 0);

	/* Ed25519 signs with sign.eddsa; the sign slot's default allowed set for
	   an ed25519 key is sign.eddsa (not sign.ecdsa), and the daemon now
	   enforces it. */
	size_t sig_len = 0;
	unsigned char *sig = sign_wire(ctx, "SIGN 0 sign.eddsa",
				       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				       &sig_len);
	ASSERT(sig_len > 0);
	free(sig);

	ASSERT_EQ(client_command_ok(ctx, "LOGOUT"), (gpg_error_t) 0);
	client_disconnect(ctx);
}

TEST(test_wrong_pin)
{
	assuan_context_t ctx = connect_client();

	ASSERT_EQ(client_command_ok(ctx, "CREATE_TOKEN pintest correct adminpin"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "OPEN_SESSION pintest"),
		  (gpg_error_t) 0);
	ASSERT_NEQ(client_command_ok(ctx, "LOGIN wrong"), (gpg_error_t) 0);

	client_disconnect(ctx);
}

TEST(test_change_pin)
{
	assuan_context_t ctx = connect_client();

	ASSERT_EQ(client_command_ok(ctx, "CREATE_TOKEN cpkey oldpin adminpin"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "OPEN_SESSION cpkey"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "LOGIN oldpin"), (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "CHANGE_PIN newpin"), (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "LOGOUT"), (gpg_error_t) 0);

	/* Old PIN should fail now */
	ASSERT_NEQ(client_command_ok(ctx, "LOGIN oldpin"), (gpg_error_t) 0);

	/* New PIN should work */
	ASSERT_EQ(client_command_ok(ctx, "LOGIN newpin"), (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "LOGOUT"), (gpg_error_t) 0);

	client_disconnect(ctx);
}

TEST(test_envelope_login_genkey_sign)
{
	assuan_context_t ctx = connect_client();

	ASSERT_EQ(client_command_ok(ctx, "CREATE_TOKEN envtok 1234 adminpin"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "OPEN_SESSION envtok"),
		  (gpg_error_t) 0);
	/* empty-token login must succeed now (keywrap anchors the PIN) */
	ASSERT_EQ(client_command_ok(ctx, "LOGIN 1234"), (gpg_error_t) 0);
	/* GENKEY no longer takes a trailing PIN arg */
	ASSERT_EQ(client_command_ok(ctx, "GENKEY 0 ed25519"), (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "LOGOUT"), (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "LOGIN 1234"), (gpg_error_t) 0);

	/* Sign a 32-byte digest with the sign slot */
	size_t sig_len = 0;
	unsigned char *sig = sign_wire(ctx, "SIGN 0 sign.eddsa",
				       "0000000000000000000000000000000000000000000000000000000000000000",
				       &sig_len);
	ASSERT(sig_len > 0);
	free(sig);

	/* Wrong PIN is rejected */
	ASSERT_EQ(client_command_ok(ctx, "LOGOUT"), (gpg_error_t) 0);
	ASSERT_NEQ(client_command_ok(ctx, "LOGIN 9999"), (gpg_error_t) 0);

	client_disconnect(ctx);
}

TEST(test_get_attribute)
{
	assuan_context_t ctx = connect_client();

	ASSERT_EQ(client_command_ok(ctx, "CREATE_TOKEN attrkey pin1 adminpin"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "OPEN_SESSION attrkey"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "LOGIN pin1"), (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "GENKEY 0 nistp256"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "LOGOUT"), (gpg_error_t) 0);

	/* Should be able to get public key attribute without login */
	char *algo = cmd_data_str(ctx, "GET_ATTRIBUTE algorithm");
	ASSERT(strstr(algo, "nistp256") != NULL);
	free(algo);

	size_t len = 0;
	char *pubkey = cmd_data(ctx, "GET_ATTRIBUTE public_key", &len);
	ASSERT(len > 0);
	free(pubkey);

	client_disconnect(ctx);
}

TEST(test_mechanism_list)
{
	assuan_context_t ctx = connect_client();

	char *list = cmd_data_str(ctx, "GET_MECHANISM_LIST");
	ASSERT(strstr(list, "sign.rsa-pkcs1") != NULL);
	ASSERT(strstr(list, "sign.ecdsa") != NULL);
	free(list);

	client_disconnect(ctx);
}

/*
 * Was test_scdaemon_serialno / test_scdaemon_readkey, which probed a real
 * rsa2048 token's identity and public key via the now-deleted scdaemon
 * SERIALNO/READKEY daemon commands. Same coverage -- a live client can pull
 * a freshly-generated token's serial and public key back out -- through the
 * neutral GET_ATTRIBUTE face instead (the scd-proxy's own SERIALNO/READKEY
 * translation is exercised by the gpg_scd/keytocard shell tests).
 */
TEST(test_neutral_get_attribute_after_genkey)
{
	assuan_context_t ctx = connect_client();

	ASSERT_EQ(client_command_ok(ctx, "CREATE_TOKEN scdkey pin1 adminpin"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "OPEN_SESSION scdkey"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "LOGIN pin1"), (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "GENKEY 0 rsa2048"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "LOGOUT"), (gpg_error_t) 0);

	/* GET_ATTRIBUTE serial works without login (was: SERIALNO). */
	size_t len = 0;
	char *serial = cmd_data(ctx, "GET_ATTRIBUTE serial", &len);
	ASSERT(len > 0);
	free(serial);

	/* GET_ATTRIBUTE public_key returns the generated key (was: READKEY
	   OPENPGP.1). */
	len = 0;
	char *pubkey = cmd_data(ctx, "GET_ATTRIBUTE public_key", &len);
	ASSERT(len > 0);
	free(pubkey);

	client_disconnect(ctx);
}

/*
 * The scdaemon PKSIGN/PKAUTH/PKDECRYPT daemon commands were removed once the
 * scd-proxy began translating gpg-agent's PK* into the neutral SIGN/DECRYPT
 * interface (which the test_sign_* / test_decrypt_* cases above already cover);
 * there is no longer a daemon-side PKSIGN handler to exercise here.
 */

TEST(test_multiple_sessions)
{
	/* Each connection to the daemon forks a new child,
	   so multiple clients can work independently. */
	assuan_context_t ctx1 = connect_client();
	assuan_context_t ctx2 = connect_client();

	ASSERT_EQ(client_command_ok(ctx1, "CREATE_TOKEN multi1 pin1 adminpin"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx2, "CREATE_TOKEN multi2 pin2 adminpin"),
		  (gpg_error_t) 0);

	/* Both should see both tokens */
	char *list1 = cmd_status_str(ctx1, "LIST_TOKENS");
	ASSERT(strstr(list1, "multi1") != NULL);
	ASSERT(strstr(list1, "multi2") != NULL);
	free(list1);

	/* Work on different tokens concurrently */
	ASSERT_EQ(client_command_ok(ctx1, "OPEN_SESSION multi1"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx2, "OPEN_SESSION multi2"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx1, "LOGIN pin1"), (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx2, "LOGIN pin2"), (gpg_error_t) 0);

	ASSERT_EQ(client_command_ok(ctx1, "LOGOUT"), (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx2, "LOGOUT"), (gpg_error_t) 0);

	client_disconnect(ctx1);
	client_disconnect(ctx2);
}

/*
 * Was test_checkpin_lockout, which drove the retry counter through the
 * now-deleted scdaemon CHECKPIN command. session_login() (LOGIN) unwraps the
 * token keywrap via the very same throttled pin_unwrap_mk() CHECKPIN used,
 * so LOGIN exercises the identical lockout path (the scd-proxy's own
 * CHECKPIN translation just calls LOGIN under the hood -- see Task 8/9).
 */
TEST(test_login_pin_lockout)
{
	assuan_context_t ctx = connect_client();

	/* Dedicated token so this does not exhaust a PIN counter other tests
	   depend on. The token PIN retry counter must be enforced through
	   LOGIN: it must not be an unthrottled PIN-guessing oracle. */
	ASSERT_EQ(client_command_ok(ctx, "CREATE_TOKEN cplock secret adminpin"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "OPEN_SESSION cplock"),
		  (gpg_error_t) 0);

	/* 3 wrong PINs via LOGIN exhaust the retry counter. */
	ASSERT_NEQ(client_command_ok(ctx, "LOGIN wrong"), (gpg_error_t) 0);
	ASSERT_NEQ(client_command_ok(ctx, "LOGIN wrong"), (gpg_error_t) 0);
	ASSERT_NEQ(client_command_ok(ctx, "LOGIN wrong"), (gpg_error_t) 0);

	/* Now even the correct PIN is rejected: the lockout tripped. */
	ASSERT_NEQ(client_command_ok(ctx, "LOGIN secret"), (gpg_error_t) 0);

	client_disconnect(ctx);
}

/*
 * UNBLOCK_TOKEN restores a locked token's retry counter after admin-PIN
 * verification, without touching the keywrap: the user's original PIN logs
 * in again afterwards. This is the recovery path for an accidental lockout
 * (e.g. ssh-add trying one PIN against several tokens).
 */
TEST(test_unblock_token)
{
	assuan_context_t ctx = connect_client();

	ASSERT_EQ(client_command_ok(ctx, "CREATE_TOKEN ublk secret adminpin"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "OPEN_SESSION ublk"),
		  (gpg_error_t) 0);

	/* Lock it: 3 wrong PINs exhaust the retry counter. */
	ASSERT_NEQ(client_command_ok(ctx, "LOGIN wrong"), (gpg_error_t) 0);
	ASSERT_NEQ(client_command_ok(ctx, "LOGIN wrong"), (gpg_error_t) 0);
	ASSERT_NEQ(client_command_ok(ctx, "LOGIN wrong"), (gpg_error_t) 0);
	/* Even the correct PIN is now rejected. */
	ASSERT_NEQ(client_command_ok(ctx, "LOGIN secret"), (gpg_error_t) 0);

	/* Admin unblock restores the counter. */
	ASSERT_EQ(client_command_ok(ctx, "UNBLOCK_TOKEN ublk adminpin"),
		  (gpg_error_t) 0);

	/* The original PIN works again -- keys were never destroyed. */
	ASSERT_EQ(client_command_ok(ctx, "LOGIN secret"), (gpg_error_t) 0);

	client_disconnect(ctx);
}

/*
 * A wrong admin PIN must NOT reset the counter: the token stays locked.
 */
TEST(test_unblock_wrong_admin_pin)
{
	assuan_context_t ctx = connect_client();

	ASSERT_EQ(client_command_ok(ctx, "CREATE_TOKEN ublk2 secret adminpin"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "OPEN_SESSION ublk2"),
		  (gpg_error_t) 0);
	ASSERT_NEQ(client_command_ok(ctx, "LOGIN wrong"), (gpg_error_t) 0);
	ASSERT_NEQ(client_command_ok(ctx, "LOGIN wrong"), (gpg_error_t) 0);
	ASSERT_NEQ(client_command_ok(ctx, "LOGIN wrong"), (gpg_error_t) 0);

	/* Wrong admin PIN: rejected, and the token remains locked. */
	ASSERT_NEQ(client_command_ok(ctx, "UNBLOCK_TOKEN ublk2 wrongadmin"),
		   (gpg_error_t) 0);
	ASSERT_NEQ(client_command_ok(ctx, "LOGIN secret"), (gpg_error_t) 0);

	client_disconnect(ctx);
}

/*
 * Unblocking a token that does not exist reports NOT_FOUND (after the admin
 * PIN checks out).
 */
TEST(test_unblock_unknown_label)
{
	assuan_context_t ctx = connect_client();

	ASSERT_EQ(gpg_err_code(client_command_ok(ctx,
			       "UNBLOCK_TOKEN nosuchtoken adminpin")),
		  GPG_ERR_NOT_FOUND);

	client_disconnect(ctx);
}

/*
 * Regression test for the DECRYPT-on-the-command-line truncation bug: an
 * rsa4096 ciphertext is 512 bytes, i.e. 1024 hex characters, which together
 * with the "DECRYPT <slot> <mechanism> " prefix overflows the Assuan line
 * length limit when sent inline. This exercises the real wire path -- the
 * DECRYPT command line plus an out-of-band CIPHERTEXT INQUIRE, via
 * client_command_data_reply() -- rather than calling op_decrypt() directly,
 * so it would have failed against the old inline-hex cmd_decrypt.
 */
TEST(test_decrypt_rsa4096_wire)
{
	assuan_context_t ctx = connect_client();

	ASSERT_EQ(client_command_ok(ctx, "CREATE_TOKEN rsa4096dec pin1 adminpin"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "OPEN_SESSION rsa4096dec"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "LOGIN pin1"), (gpg_error_t) 0);

	size_t keydata_len = 0;
	unsigned char *keydata = load_fixture_rsa4096(&keydata_len);

	/* Import the fixture private key into the encrypt slot (slot 1). */
	ASSERT_EQ(client_command_with_data(ctx, "IMPORT_SLOT 1",
					   keydata, keydata_len),
		  (gpg_error_t) 0);

	/* Encrypt a known plaintext with the fixture's PUBLIC key, via
	   libgcrypt (through the shared crypto_rsa helpers), independent of
	   the daemon. */
	unsigned char *pubkey = NULL;
	size_t pubkey_len = 0;
	ASSERT_EQ(crypto_rsa_extract_pubkey(keydata, keydata_len,
					    &pubkey, &pubkey_len), 0);
	free(keydata);

	static const unsigned char plaintext[] =
	    "reliquary rsa4096 DECRYPT wire regression -- exceeds one Assuan line as hex";
	unsigned char *ciphertext = NULL;
	size_t ciphertext_len = 0;
	ASSERT_EQ(crypto_rsa_encrypt_pkcs1(pubkey, pubkey_len,
					   plaintext, sizeof(plaintext),
					   &ciphertext, &ciphertext_len), 0);
	free(pubkey);

	/* The actual fix under test: ciphertext travels via INQUIRE, not
	   hex on the DECRYPT command line. */
	unsigned char *out = NULL;
	size_t out_len = 0;
	ASSERT_EQ(client_command_data_reply(ctx, "DECRYPT 1 decrypt.rsa-pkcs1",
					    ciphertext, ciphertext_len,
					    &out, &out_len), (gpg_error_t) 0);
	free(ciphertext);

	ASSERT_EQ(out_len, sizeof(plaintext));
	ASSERT_MEM_EQ(out, plaintext, sizeof(plaintext));
	free(out);

	ASSERT_EQ(client_command_ok(ctx, "LOGOUT"), (gpg_error_t) 0);
	client_disconnect(ctx);
}

/* Verify a sign.rsa-pkcs1 raw signature (op_sign's crypto_rsa_sign_raw):
   the daemon does not hash or wrap msg -- it embeds it directly as the
   message body of a PKCS#1 v1.5 type-1 padded block (0x00 0x01 [0xFF...]
   0x00 [msg]) and signs that raw. Reconstruct the same padded block here
   and verify with libgcrypt's raw RSA public-key operation. */
static int
verify_rsa_pkcs1_raw(const unsigned char *pubkey, size_t pubkey_len,
		     const unsigned char *msg, size_t msg_len,
		     const unsigned char *sig, size_t sig_len)
{
	gcry_sexp_t pub = NULL;
	if (gcry_sexp_new(&pub, pubkey, pubkey_len, 0) != 0)
		return -1;

	unsigned int nbits = gcry_pk_get_nbits(pub);
	size_t k = (nbits + 7) / 8;
	if (k == 0 || msg_len + 11 > k) {
		gcry_sexp_release(pub);
		return -1;
	}

	unsigned char *padded = malloc(k);
	if (!padded) {
		gcry_sexp_release(pub);
		return -1;
	}
	padded[0] = 0x00;
	padded[1] = 0x01;
	memset(padded + 2, 0xFF, k - msg_len - 3);
	padded[k - msg_len - 1] = 0x00;
	memcpy(padded + k - msg_len, msg, msg_len);

	gcry_sexp_t data = NULL, sig_sexp = NULL;
	int rc = -1;
	if (gcry_sexp_build(&data, NULL, "(data (flags raw) (value %b))",
			    (int)k, padded) == 0
	    && gcry_sexp_build(&sig_sexp, NULL, "(sig-val (rsa (s %b)))",
			       (int)sig_len, sig) == 0)
		rc = gcry_pk_verify(sig_sexp, data, pub) ? -1 : 0;

	free(padded);
	if (data)
		gcry_sexp_release(data);
	if (sig_sexp)
		gcry_sexp_release(sig_sexp);
	gcry_sexp_release(pub);
	return rc;
}

TEST(test_sign_rsa4096_wire)
{
	assuan_context_t ctx = connect_client();

	ASSERT_EQ(client_command_ok(ctx, "CREATE_TOKEN rsa4096sign pin1 adminpin"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "OPEN_SESSION rsa4096sign"),
		  (gpg_error_t) 0);
	ASSERT_EQ(client_command_ok(ctx, "LOGIN pin1"), (gpg_error_t) 0);

	size_t keydata_len = 0;
	unsigned char *keydata = load_fixture_rsa4096(&keydata_len);

	/* Import the fixture private key into the sign slot (slot 0). */
	ASSERT_EQ(client_command_with_data(ctx, "IMPORT_SLOT 0",
					   keydata, keydata_len),
		  (gpg_error_t) 0);

	unsigned char *pubkey = NULL;
	size_t pubkey_len = 0;
	ASSERT_EQ(crypto_rsa_extract_pubkey(keydata, keydata_len,
					    &pubkey, &pubkey_len), 0);
	free(keydata);

	/* 501-byte pre-formatted signing input: the largest sign.rsa-pkcs1 raw
	   sign can take against a 512-byte (rsa4096) modulus (msg_len + 11 <=
	   k). Its hex encoding (1002 chars) would not have reliably fit on
	   the old SIGN command line alongside the slot/mechanism prefix and
	   would have been truncated -- the actual fix under test is that it
	   instead travels via INQUIRE VALUE. */
	unsigned char msg[501];
	for (size_t i = 0; i < sizeof(msg); i++)
		msg[i] = (unsigned char)(i * 7 + 1);

	unsigned char *sig = NULL;
	size_t sig_len = 0;
	ASSERT_EQ(client_command_data_reply(ctx, "SIGN 0 sign.rsa-pkcs1",
					    msg, sizeof(msg),
					    &sig, &sig_len), (gpg_error_t) 0);
	ASSERT(sig_len > 0);

	ASSERT_EQ(verify_rsa_pkcs1_raw(pubkey, pubkey_len, msg, sizeof(msg),
				       sig, sig_len), 0);
	free(pubkey);
	free(sig);

	ASSERT_EQ(client_command_ok(ctx, "LOGOUT"), (gpg_error_t) 0);
	client_disconnect(ctx);
}

TEST(test_admin_state_corrupt_fails_open)
{
	assuan_context_t ctx = connect_client();

	/* Overwrite admin-state with a file that still contains the
	   "retries " marker but a non-numeric value after it. A naive atoi()
	   parse would read this as 0 (immediate lockout, a fail-closed DoS);
	   the parser must instead recognize it as unparseable and fail open
	   (treat it as a full retry count), not brick the store. */
	char path[600];
	snprintf(path, sizeof(path), "%s/admin-state", store_dir);
	FILE *f = fopen(path, "wb");
	ASSERT_NOT_NULL(f);
	static const char garbage[] = "(admin-state (retries GARBAGE))";
	ASSERT_EQ(fwrite(garbage, 1, sizeof(garbage) - 1, f),
		  sizeof(garbage) - 1);
	fclose(f);

	/* The correct admin PIN must still succeed despite the corrupt file. */
	ASSERT_EQ(client_command_ok(ctx, "CREATE_TOKEN admstatecorrupt 1 adminpin"),
		  (gpg_error_t) 0);

	client_disconnect(ctx);
}

TEST(test_admin_pin_lockout)
{
	assuan_context_t ctx = connect_client();

	/* 3 wrong admin PINs, then even the right one is locked out.
	   This is the last test to run: it permanently exhausts the shared
	   store's admin-PIN retry counter, so no admin-gated command after
	   it in this process can succeed with the correct PIN either. */
	ASSERT_NEQ(client_command_ok(ctx, "CREATE_TOKEN admlock 1 wrong"),
		   (gpg_error_t) 0);
	ASSERT_NEQ(client_command_ok(ctx, "CREATE_TOKEN admlock 1 wrong"),
		   (gpg_error_t) 0);
	ASSERT_NEQ(client_command_ok(ctx, "CREATE_TOKEN admlock 1 wrong"),
		   (gpg_error_t) 0);
	ASSERT_NEQ(client_command_ok(ctx, "CREATE_TOKEN admlock 1 adminpin"),
		   (gpg_error_t) 0);

	client_disconnect(ctx);
}

static void
init_store(void)
{
	assuan_context_t ctx = connect_client();
	ASSERT_EQ(client_command_ok(ctx, "INIT_STORE adminpin"),
		  (gpg_error_t) 0);
	client_disconnect(ctx);
}

TEST_MAIN_BEGIN("test_daemon_integration")
    start_daemon();
init_store();
RUN(test_create_token_and_list);
RUN(test_login_sign_rsa);
RUN(test_genkey_rsa1024_rejected);
RUN(test_login_sign_ec);
RUN(test_login_sign_ed25519);
RUN(test_wrong_pin);
RUN(test_change_pin);
RUN(test_envelope_login_genkey_sign);
RUN(test_get_attribute);
RUN(test_mechanism_list);
RUN(test_neutral_get_attribute_after_genkey);
RUN(test_multiple_sessions);
RUN(test_decrypt_rsa4096_wire);
RUN(test_sign_rsa4096_wire);
RUN(test_login_pin_lockout);
RUN(test_unblock_token);
RUN(test_unblock_wrong_admin_pin);
RUN(test_unblock_unknown_label);
RUN(test_admin_state_corrupt_fails_open);
RUN(test_admin_pin_lockout);
cleanup();
TEST_MAIN_END
