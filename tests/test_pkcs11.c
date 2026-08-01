/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "testutil.h"
#include "pkcs11.h"
#include "server.h"
#include "session.h"
#include "crypto.h"
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *store = "/tmp/test_reliquary_pkcs11";
static const char *sock_path = "/tmp/test_reliquary_pkcs11.sock";
static pid_t daemon_pid = 0;

static void
cleanup(void)
{
	if (daemon_pid > 0) {
		kill(daemon_pid, SIGTERM);
		waitpid(daemon_pid, NULL, 0);
		daemon_pid = 0;
	}
	unlink(sock_path);
	char cmd[512];
	snprintf(cmd, sizeof(cmd), "rm -rf %s", store);
	ASSERT_EQ(system(cmd), 0);
}

static void
start_daemon(void)
{
	mkdir(store, 0700);

	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ASSERT(fd >= 0);

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
	unlink(sock_path);
	ASSERT_EQ(bind(fd, (struct sockaddr *)&addr, sizeof(addr)), 0);
	ASSERT_EQ(listen(fd, 5), 0);

	pid_t pid = fork();
	ASSERT(pid >= 0);

	if (pid == 0) {
		crypto_init();
		while (1) {
			int client_fd = accept(fd, NULL, NULL);
			if (client_fd < 0)
				break;

			pid_t child = fork();
			if (child == 0) {
				close(fd);
				session_t sess;
				session_init(&sess, getuid(), store);
				assuan_context_t ctx;
				if (server_init(&ctx, client_fd, &sess) == 0)
					server_run(ctx);
				_exit(0);
			}
			close(client_fd);
		}
		_exit(0);
	}

	close(fd);
	daemon_pid = pid;
	setenv("RELIQUARY_SOCKET", sock_path, 1);
	usleep(50000);
}

/* Create a token with a key by connecting directly to the daemon */
static void
create_token(const char *label, const char *algo, const char *pin)
{
	assuan_context_t ctx;
	ASSERT_EQ(assuan_new(&ctx), (gpg_error_t) 0);
	ASSERT_EQ(assuan_socket_connect(ctx, sock_path, 0, 0), (gpg_error_t) 0);

	/* Initialize store (ignore error if already done) */
	assuan_transact(ctx, "INIT_STORE adminpin", NULL, NULL, NULL, NULL,
			NULL, NULL);

	char cmd[1024];
	snprintf(cmd, sizeof(cmd), "CREATE_TOKEN %s %s adminpin", label, pin);
	gpg_error_t err =
	    assuan_transact(ctx, cmd, NULL, NULL, NULL, NULL, NULL, NULL);
	ASSERT_EQ(err, (gpg_error_t) 0);

	snprintf(cmd, sizeof(cmd), "OPEN_SESSION %s", label);
	err = assuan_transact(ctx, cmd, NULL, NULL, NULL, NULL, NULL, NULL);
	ASSERT_EQ(err, (gpg_error_t) 0);

	snprintf(cmd, sizeof(cmd), "LOGIN %s", pin);
	err = assuan_transact(ctx, cmd, NULL, NULL, NULL, NULL, NULL, NULL);
	ASSERT_EQ(err, (gpg_error_t) 0);

	snprintf(cmd, sizeof(cmd), "GENKEY 0 %s", algo);
	err = assuan_transact(ctx, cmd, NULL, NULL, NULL, NULL, NULL, NULL);
	ASSERT_EQ(err, (gpg_error_t) 0);

	assuan_transact(ctx, "CLOSE_SESSION", NULL, NULL, NULL, NULL, NULL,
			NULL);
	assuan_release(ctx);
}

TEST(test_get_function_list)
{
	CK_FUNCTION_LIST_PTR fl = NULL;
	ASSERT_EQ(C_GetFunctionList(&fl), CKR_OK);
	ASSERT_NOT_NULL(fl);
	ASSERT_EQ(fl->version.major, 3);
	ASSERT_EQ(fl->version.minor, 0);
}

TEST(test_init_and_finalize)
{
	start_daemon();
	CK_FUNCTION_LIST_PTR fl;
	C_GetFunctionList(&fl);

	ASSERT_EQ(fl->C_Initialize(NULL), CKR_OK);
	ASSERT_EQ(fl->C_Initialize(NULL), CKR_CRYPTOKI_ALREADY_INITIALIZED);
	ASSERT_EQ(fl->C_Finalize(NULL), CKR_OK);
	ASSERT_EQ(fl->C_Finalize(NULL), CKR_CRYPTOKI_NOT_INITIALIZED);
	cleanup();
}

TEST(test_slot_enumeration)
{
	start_daemon();
	create_token("testkey", "rsa2048", "1234");

	CK_FUNCTION_LIST_PTR fl;
	C_GetFunctionList(&fl);
	ASSERT_EQ(fl->C_Initialize(NULL), CKR_OK);

	CK_ULONG count = 0;
	ASSERT_EQ(fl->C_GetSlotList(CK_TRUE, NULL, &count), CKR_OK);
	ASSERT(count >= 1);

	CK_SLOT_ID slots[16];
	CK_ULONG n = 16;
	ASSERT_EQ(fl->C_GetSlotList(CK_TRUE, slots, &n), CKR_OK);
	ASSERT(n >= 1);

	CK_TOKEN_INFO tinfo;
	ASSERT_EQ(fl->C_GetTokenInfo(slots[0], &tinfo), CKR_OK);
	ASSERT(memcmp(tinfo.label, "testkey", 7) == 0);

	fl->C_Finalize(NULL);
	cleanup();
}

TEST(test_session_login_sign)
{
	start_daemon();
	create_token("signtest", "rsa2048", "mypin");

	CK_FUNCTION_LIST_PTR fl;
	C_GetFunctionList(&fl);
	ASSERT_EQ(fl->C_Initialize(NULL), CKR_OK);

	CK_SLOT_ID slots[16];
	CK_ULONG n = 16;
	fl->C_GetSlotList(CK_TRUE, slots, &n);

	CK_SESSION_HANDLE session;
	ASSERT_EQ(fl->C_OpenSession
		  (slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL,
		   &session), CKR_OK);

	CK_UTF8CHAR pin[] = "mypin";
	ASSERT_EQ(fl->C_Login(session, CKU_USER, pin, 5), CKR_OK);

	/* Find private key */
	CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE tmpl[] = { {CKA_CLASS, &cls, sizeof(cls)}
	};
	ASSERT_EQ(fl->C_FindObjectsInit(session, tmpl, 1), CKR_OK);

	CK_OBJECT_HANDLE obj;
	CK_ULONG found;
	ASSERT_EQ(fl->C_FindObjects(session, &obj, 1, &found), CKR_OK);
	ASSERT_EQ(found, (CK_ULONG) 1);
	ASSERT_EQ(fl->C_FindObjectsFinal(session), CKR_OK);

	/* Sign -- CKM_RSA_PKCS expects DigestInfo */
	CK_MECHANISM mech = { CKM_RSA_PKCS, NULL, 0 };
	ASSERT_EQ(fl->C_SignInit(session, &mech, obj), CKR_OK);

	static const CK_BYTE sha256_prefix[] = {
		0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
		0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
		0x00, 0x04, 0x20
	};
	CK_BYTE data[51];
	memcpy(data, sha256_prefix, 19);
	memset(data + 19, 0xAA, 32);
	CK_BYTE sig[512];
	CK_ULONG sig_len = sizeof(sig);
	ASSERT_EQ(fl->C_Sign(session, data, sizeof(data), sig, &sig_len),
		  CKR_OK);
	ASSERT(sig_len > 0);

	fl->C_Logout(session);
	fl->C_CloseSession(session);
	fl->C_Finalize(NULL);
	cleanup();
}

TEST(test_wrong_pin)
{
	start_daemon();
	create_token("pintest", "rsa2048", "right");

	CK_FUNCTION_LIST_PTR fl;
	C_GetFunctionList(&fl);
	fl->C_Initialize(NULL);

	CK_SLOT_ID slots[16];
	CK_ULONG n = 16;
	fl->C_GetSlotList(CK_TRUE, slots, &n);

	CK_SESSION_HANDLE session;
	fl->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
			  NULL, &session);

	CK_UTF8CHAR bad_pin[] = "wrong";
	ASSERT_EQ(fl->C_Login(session, CKU_USER, bad_pin, 5),
		  CKR_PIN_INCORRECT);

	fl->C_CloseSession(session);
	fl->C_Finalize(NULL);
	cleanup();
}

/*
 * A zero-length PIN must be rejected locally (CKR_PIN_INCORRECT) without
 * a round trip to the daemon -- reliquary has no protected-authentication-
 * path, so an empty PIN can never unwrap the master key.  This also
 * guards against the daemon's LOGIN-with-empty-line NEEDPIN-on-demand
 * behavior (added for the scd-proxy's CHECKPIN relay path) reaching this
 * module, which has no inquire callback to answer such a prompt.
 */
TEST(test_empty_pin_rejected)
{
	start_daemon();
	create_token("emptypintest", "rsa2048", "1234");

	CK_FUNCTION_LIST_PTR fl;
	C_GetFunctionList(&fl);
	fl->C_Initialize(NULL);

	CK_SLOT_ID slots[16];
	CK_ULONG n = 16;
	fl->C_GetSlotList(CK_TRUE, slots, &n);

	CK_SESSION_HANDLE session;
	fl->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
			  NULL, &session);

	ASSERT_EQ(fl->C_Login(session, CKU_USER, NULL, 0), CKR_PIN_INCORRECT);

	fl->C_CloseSession(session);
	fl->C_Finalize(NULL);
	cleanup();
}

TEST(test_pss_bad_hash_rejected)
{
	start_daemon();
	create_token("psstest", "rsa2048", "1234");

	CK_FUNCTION_LIST_PTR fl;
	C_GetFunctionList(&fl);
	ASSERT_EQ(fl->C_Initialize(NULL), CKR_OK);

	CK_SLOT_ID slots[16];
	CK_ULONG n = 16;
	fl->C_GetSlotList(CK_TRUE, slots, &n);

	CK_SESSION_HANDLE session;
	ASSERT_EQ(fl->C_OpenSession
		  (slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL,
		   &session), CKR_OK);

	CK_UTF8CHAR pin[] = "1234";
	ASSERT_EQ(fl->C_Login(session, CKU_USER, pin, 4), CKR_OK);

	CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE tmpl[] = { {CKA_CLASS, &cls, sizeof(cls)}
	};
	ASSERT_EQ(fl->C_FindObjectsInit(session, tmpl, 1), CKR_OK);

	CK_OBJECT_HANDLE obj;
	CK_ULONG found;
	ASSERT_EQ(fl->C_FindObjects(session, &obj, 1, &found), CKR_OK);
	ASSERT_EQ(found, (CK_ULONG) 1);
	ASSERT_EQ(fl->C_FindObjectsFinal(session), CKR_OK);

	/* SHA-384 is not the supported PSS hash (SHA-256 only); the stub
	 * must fail loud instead of silently signing under SHA-256. */
	CK_RSA_PKCS_PSS_PARAMS pss_params = {
		.hashAlg = CKM_SHA384,
		.mgf = CKG_MGF1_SHA384,
		.sLen = 32,
	};
	CK_MECHANISM mech = { CKM_RSA_PKCS_PSS, &pss_params,
		sizeof(pss_params)
	};
	ASSERT_EQ(fl->C_SignInit(session, &mech, obj),
		  CKR_MECHANISM_PARAM_INVALID);

	fl->C_Logout(session);
	fl->C_CloseSession(session);
	fl->C_Finalize(NULL);
	cleanup();
}

TEST(test_rsa_x509_signinit_rejected)
{
	start_daemon();
	create_token("rsax509test", "rsa2048", "1234");

	CK_FUNCTION_LIST_PTR fl;
	C_GetFunctionList(&fl);
	ASSERT_EQ(fl->C_Initialize(NULL), CKR_OK);

	CK_SLOT_ID slots[16];
	CK_ULONG n = 16;
	fl->C_GetSlotList(CK_TRUE, slots, &n);

	CK_SESSION_HANDLE session;
	ASSERT_EQ(fl->C_OpenSession
		  (slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL,
		   &session), CKR_OK);

	CK_UTF8CHAR pin[] = "1234";
	ASSERT_EQ(fl->C_Login(session, CKU_USER, pin, 4), CKR_OK);

	CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE tmpl[] = { {CKA_CLASS, &cls, sizeof(cls)}
	};
	ASSERT_EQ(fl->C_FindObjectsInit(session, tmpl, 1), CKR_OK);

	CK_OBJECT_HANDLE obj;
	CK_ULONG found;
	ASSERT_EQ(fl->C_FindObjects(session, &obj, 1, &found), CKR_OK);
	ASSERT_EQ(found, (CK_ULONG) 1);
	ASSERT_EQ(fl->C_FindObjectsFinal(session), CKR_OK);

	/* CKM_RSA_X_509 is decrypt-only (raw RSA); wire_mech() must reject
	 * it for the sign operation at init time rather than admitting it
	 * and letting the daemon fail it later at C_Sign. */
	CK_MECHANISM mech = { CKM_RSA_X_509, NULL, 0 };
	ASSERT_EQ(fl->C_SignInit(session, &mech, obj), CKR_MECHANISM_INVALID);

	fl->C_Logout(session);
	fl->C_CloseSession(session);
	fl->C_Finalize(NULL);
	cleanup();
}

TEST(test_mechanism_list)
{
	start_daemon();
	create_token("mechtest", "rsa2048", "1234");

	CK_FUNCTION_LIST_PTR fl;
	C_GetFunctionList(&fl);
	fl->C_Initialize(NULL);

	CK_SLOT_ID slots[16];
	CK_ULONG n = 16;
	fl->C_GetSlotList(CK_TRUE, slots, &n);

	CK_ULONG mech_count = 0;
	ASSERT_EQ(fl->C_GetMechanismList(slots[0], NULL, &mech_count), CKR_OK);
	ASSERT_EQ(mech_count, (CK_ULONG) 6);

	CK_MECHANISM_TYPE mechs[16];
	CK_ULONG mc = 16;
	ASSERT_EQ(fl->C_GetMechanismList(slots[0], mechs, &mc), CKR_OK);
	ASSERT_EQ(mc, (CK_ULONG) 6);

	fl->C_Finalize(NULL);
	cleanup();
}

TEST(test_disconnected_token_excluded_from_slots)
{
	start_daemon();
	create_token("live", "rsa2048", "1234");
	create_token("gone", "rsa2048", "1234");

	/* Disconnect "gone" directly via the daemon's DISCONNECT_TOKEN
	   command, same as test_daemon.c's disconnect tests. */
	assuan_context_t actx;
	ASSERT_EQ(assuan_new(&actx), (gpg_error_t) 0);
	ASSERT_EQ(assuan_socket_connect(actx, sock_path, 0, 0),
		  (gpg_error_t) 0);
	ASSERT_EQ(assuan_transact(actx, "DISCONNECT_TOKEN gone", NULL, NULL,
				  NULL, NULL, NULL, NULL), (gpg_error_t) 0);
	assuan_release(actx);

	CK_FUNCTION_LIST_PTR fl;
	C_GetFunctionList(&fl);
	ASSERT_EQ(fl->C_Initialize(NULL), CKR_OK);

	CK_SLOT_ID slots[16];
	CK_ULONG n = 16;
	ASSERT_EQ(fl->C_GetSlotList(CK_TRUE, slots, &n), CKR_OK);

	int saw_live = 0, saw_gone = 0;
	for (CK_ULONG i = 0; i < n; i++) {
		CK_TOKEN_INFO tinfo;
		ASSERT_EQ(fl->C_GetTokenInfo(slots[i], &tinfo), CKR_OK);
		if (memcmp(tinfo.label, "live", 4) == 0)
			saw_live = 1;
		if (memcmp(tinfo.label, "gone", 4) == 0)
			saw_gone = 1;
	}
	ASSERT_EQ(saw_live, 1);
	ASSERT_EQ(saw_gone, 0);

	fl->C_Finalize(NULL);
	cleanup();
}

TEST_MAIN_BEGIN("test_pkcs11")
    ASSERT_EQ(crypto_init(), 0);
RUN(test_get_function_list);
RUN(test_init_and_finalize);
RUN(test_slot_enumeration);
RUN(test_session_login_sign);
RUN(test_wrong_pin);
RUN(test_empty_pin_rejected);
RUN(test_pss_bad_hash_rejected);
RUN(test_rsa_x509_signinit_rejected);
RUN(test_mechanism_list);
RUN(test_disconnected_token_excluded_from_slots);
TEST_MAIN_END
