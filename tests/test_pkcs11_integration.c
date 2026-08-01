/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "testutil.h"
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <gcrypt.h>

/* Use the same vendored PKCS#11 header as the shared library. */
#include "pkcs11.h"
#include "client.h"

typedef CK_RV(*CK_C_GetFunctionList_f) (CK_FUNCTION_LIST_PTR_PTR);

/* ---- daemon + library management ---- */

static char store_dir[] = "/tmp/test_p11int_store_XXXXXX";
static char xdg_dir[] = "/tmp/test_p11int_xdg_XXXXXX";
static char socket_path[512];
static char daemon_path[512];
static char lib_path[512];
static char tool_path[512];
static pid_t daemon_pid = -1;
static void *lib_handle = NULL;
static CK_FUNCTION_LIST_PTR fl = NULL;

static void
cleanup(void)
{
	if (fl) {
		fl->C_Finalize(NULL);
		fl = NULL;
	}
	if (lib_handle) {
		dlclose(lib_handle);
		lib_handle = NULL;
	}
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

	const char *dpath = getenv("RELIQUARYD_PATH");
	if (!dpath)
		dpath = "src/daemon/reliquaryd";
	snprintf(daemon_path, sizeof(daemon_path), "%s", dpath);

	const char *lpath = getenv("RELIQUARY_PKCS11_PATH");
	if (!lpath)
		lpath = "src/pkcs11/reliquary-pkcs11.so";
	snprintf(lib_path, sizeof(lib_path), "%s", lpath);

	const char *tpath = getenv("RELIQUARY_TOOL_PATH");
	if (!tpath)
		tpath = "src/tools/reliquary-tool";
	snprintf(tool_path, sizeof(tool_path), "%s", tpath);

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
	/* Ensure the child's pgid is set before we proceed */
	setpgid(daemon_pid, daemon_pid);

	if (wait_for_socket(socket_path, 5000) != 0) {
		fprintf(stderr, "Daemon socket did not appear at %s\n",
			socket_path);
		cleanup();
		exit(1);
	}

	/* Point the PKCS#11 library at our daemon */
	setenv("RELIQUARY_SOCKET", socket_path, 1);
}

static void
load_pkcs11(void)
{
	lib_handle = dlopen(lib_path, RTLD_NOW);
	if (!lib_handle) {
		fprintf(stderr, "dlopen(%s): %s\n", lib_path, dlerror());
		ASSERT_NOT_NULL(lib_handle);
	}

	CK_C_GetFunctionList_f get_fl = dlsym(lib_handle, "C_GetFunctionList");
	ASSERT_NOT_NULL(get_fl);
	ASSERT_EQ(get_fl(&fl), CKR_OK);
	ASSERT_NOT_NULL(fl);
}

/*
 * Read from an Assuan socket until a line starting with "OK" or "ERR"
 * appears, or EOF/error.  Returns 1 for OK, 0 for ERR, -1 for error.
 */
static int
assuan_read_response(int fd)
{
	char buf[4096];
	size_t filled = 0;

	for (;;) {
		ssize_t n = read(fd, buf + filled, sizeof(buf) - filled - 1);
		if (n <= 0)
			return -1;
		filled += (size_t)n;
		buf[filled] = '\0';

		/* Scan for complete lines */
		char *line = buf;
		char *nl;
		while ((nl = strchr(line, '\n')) != NULL) {
			*nl = '\0';
			if (strncmp(line, "OK", 2) == 0)
				return 1;
			if (strncmp(line, "ERR", 3) == 0)
				return 0;
			line = nl + 1;
		}

		/* Shift unprocessed tail to front */
		size_t tail = filled - (size_t)(line - buf);
		memmove(buf, line, tail);
		filled = tail;
	}
}

/* Send a single Assuan command and assert OK response */
static void
assuan_send_cmd(int fd, const char *fmt, ...)
{
	char cmd[512];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(cmd, sizeof(cmd), fmt, ap);
	va_end(ap);

	size_t len = strlen(cmd);
	/* Ensure newline */
	if (len == 0 || cmd[len - 1] != '\n') {
		cmd[len] = '\n';
		cmd[len + 1] = '\0';
		len++;
	}
	ssize_t written = write(fd, cmd, len);
	ASSERT_EQ(written, (ssize_t) len);

	int rc = assuan_read_response(fd);
	if (rc != 1) {
		fprintf(stderr, "Assuan command failed: %s", cmd);
		ASSERT(0);
	}
}

/* Pre-create a token via direct Assuan (PKCS#11 has no create API) */
static void
create_token_via_assuan_slot(const char *label, const char *algo,
			     const char *pin, int kslot)
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ASSERT(fd >= 0);

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
	ASSERT_EQ(connect(fd, (struct sockaddr *)&addr, sizeof(addr)), 0);

	/* Read server greeting */
	ASSERT_EQ(assuan_read_response(fd), 1);

	/* Initialize store (ignore error if already done) */
	{
		const char *init = "INIT_STORE adminpin\n";
		write(fd, init, strlen(init));
		assuan_read_response(fd);
	}

	assuan_send_cmd(fd, "CREATE_TOKEN %s %s adminpin", label, pin);
	assuan_send_cmd(fd, "OPEN_SESSION %s", label);
	assuan_send_cmd(fd, "LOGIN %s", pin);
	assuan_send_cmd(fd, "GENKEY %d %s", kslot, algo);
	assuan_send_cmd(fd, "CLOSE_SESSION");

	close(fd);
}

static void
create_token_via_assuan(const char *label, const char *algo, const char *pin)
{
	create_token_via_assuan_slot(label, algo, pin, 0);
}

/* Run reliquary-tool with argv (argv[0] must be tool_path, NULL-terminated),
 * feeding stdin_data (may be NULL) on its stdin, and require exit status 0.
 * stdout/stderr are discarded so test output stays quiet on the happy path.
 */
static void
run_tool(char *const argv[], const char *stdin_data)
{
	int inpipe[2];
	ASSERT_EQ(pipe(inpipe), 0);

	pid_t pid = fork();
	ASSERT(pid >= 0);
	if (pid == 0) {
		dup2(inpipe[0], STDIN_FILENO);
		close(inpipe[0]);
		close(inpipe[1]);
		int devnull = open("/dev/null", O_WRONLY);
		if (devnull >= 0) {
			dup2(devnull, STDOUT_FILENO);
			dup2(devnull, STDERR_FILENO);
			close(devnull);
		}
		execv(argv[0], argv);
		_exit(127);
	}
	close(inpipe[0]);
	if (stdin_data)
		(void)write(inpipe[1], stdin_data, strlen(stdin_data));
	close(inpipe[1]);

	int status = 0;
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	ASSERT(WIFEXITED(status));
	ASSERT_EQ(WEXITSTATUS(status), 0);
}

/* Whether ssh-keygen is available; the imported-Ed25519-key regression test
 * needs it to produce a real OpenSSH private key file. */
static int
have_ssh_keygen(void)
{
	return system("command -v ssh-keygen >/dev/null 2>&1") == 0;
}

/* ---- helpers ---- */

static CK_SLOT_ID
get_first_slot(void)
{
	CK_SLOT_ID slots[64];
	CK_ULONG count = 64;
	ASSERT_EQ(fl->C_GetSlotList(CK_TRUE, slots, &count), CKR_OK);
	ASSERT(count >= 1);
	return slots[0];
}

static CK_SESSION_HANDLE
open_session(CK_SLOT_ID slot)
{
	CK_SESSION_HANDLE sess;
	ASSERT_EQ(fl->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
				    NULL, NULL, &sess), CKR_OK);
	return sess;
}

static CK_OBJECT_HANDLE
find_private_key(CK_SESSION_HANDLE sess)
{
	CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE tmpl[] = { {CKA_CLASS, &cls, sizeof(cls)}
	};
	ASSERT_EQ(fl->C_FindObjectsInit(sess, tmpl, 1), CKR_OK);

	CK_OBJECT_HANDLE obj;
	CK_ULONG found;
	ASSERT_EQ(fl->C_FindObjects(sess, &obj, 1, &found), CKR_OK);
	ASSERT_EQ(found, (CK_ULONG) 1);
	ASSERT_EQ(fl->C_FindObjectsFinal(sess), CKR_OK);
	return obj;
}

/* Find the PKCS#11 slot whose token has this label (label is a space-padded
   fixed-width field, so match the prefix then require a space or end). */
static CK_SLOT_ID
find_slot_by_label(const char *label)
{
	CK_SLOT_ID slots[64];
	CK_ULONG n = 64;
	ASSERT_EQ(fl->C_GetSlotList(CK_TRUE, slots, &n), CKR_OK);
	size_t llen = strlen(label);
	for (CK_ULONG i = 0; i < n; i++) {
		CK_TOKEN_INFO ti;
		if (fl->C_GetTokenInfo(slots[i], &ti) != CKR_OK)
			continue;
		if (memcmp(ti.label, label, llen) == 0
		    && (llen >= sizeof(ti.label) || ti.label[llen] == ' '))
			return slots[i];
	}
	ASSERT(0);		/* label not found */
	return 0;
}

/* Read one CK_BBOOL attribute from a token's single private key. Reading
   usage attributes does not require login. */
static CK_BBOOL
priv_key_bool(const char *label, CK_ATTRIBUTE_TYPE type)
{
	CK_SLOT_ID slot = find_slot_by_label(label);
	CK_SESSION_HANDLE sess = open_session(slot);
	CK_OBJECT_HANDLE key = find_private_key(sess);
	CK_BBOOL v = CK_FALSE;
	CK_ATTRIBUTE t = { type, &v, sizeof(v) };
	ASSERT_EQ(fl->C_GetAttributeValue(sess, key, &t, 1), CKR_OK);
	ASSERT_EQ(fl->C_CloseSession(sess), CKR_OK);
	return v;
}

/* ---- tests ---- */

TEST(test_dlopen_and_get_function_list)
{
	ASSERT_NOT_NULL(fl);
	ASSERT_EQ(fl->version.major, 3);
	ASSERT_EQ(fl->version.minor, 0);
}

TEST(test_init_finalize)
{
	ASSERT_EQ(fl->C_Initialize(NULL), CKR_OK);
	ASSERT_EQ(fl->C_Finalize(NULL), CKR_OK);
}

TEST(test_get_info)
{
	ASSERT_EQ(fl->C_Initialize(NULL), CKR_OK);
	CK_INFO info;
	ASSERT_EQ(fl->C_GetInfo(&info), CKR_OK);
	ASSERT_EQ(info.cryptokiVersion.major, 3);
	ASSERT_EQ(info.cryptokiVersion.minor, 0);
	fl->C_Finalize(NULL);
}

TEST(test_slot_enumeration_rsa)
{
	create_token_via_assuan("rsa2k", "rsa2048", "1234");

	ASSERT_EQ(fl->C_Initialize(NULL), CKR_OK);

	CK_ULONG count = 0;
	ASSERT_EQ(fl->C_GetSlotList(CK_TRUE, NULL, &count), CKR_OK);
	ASSERT(count >= 1);

	CK_SLOT_ID slot = get_first_slot();

	CK_TOKEN_INFO tinfo;
	ASSERT_EQ(fl->C_GetTokenInfo(slot, &tinfo), CKR_OK);
	ASSERT(memcmp(tinfo.label, "rsa2k", 5) == 0);

	CK_SLOT_INFO sinfo;
	ASSERT_EQ(fl->C_GetSlotInfo(slot, &sinfo), CKR_OK);

	fl->C_Finalize(NULL);
}

TEST(test_rsa_sign_via_pkcs11)
{
	ASSERT_EQ(fl->C_Initialize(NULL), CKR_OK);

	CK_SLOT_ID slot = get_first_slot();
	CK_SESSION_HANDLE sess = open_session(slot);

	CK_UTF8CHAR pin[] = "1234";
	ASSERT_EQ(fl->C_Login(sess, CKU_USER, pin, 4), CKR_OK);

	CK_OBJECT_HANDLE key = find_private_key(sess);

	CK_MECHANISM mech = { CKM_RSA_PKCS, NULL, 0 };
	ASSERT_EQ(fl->C_SignInit(sess, &mech, key), CKR_OK);

	/* SHA-256 DigestInfo: 19-byte prefix + 32-byte hash */
	static const CK_BYTE sha256_prefix[] = {
		0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
		0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
		0x00, 0x04, 0x20
	};
	CK_BYTE data[51];
	memcpy(data, sha256_prefix, 19);
	memset(data + 19, 0xBB, 32);
	CK_BYTE sig[512];
	CK_ULONG sig_len = sizeof(sig);
	ASSERT_EQ(fl->C_Sign(sess, data, sizeof(data), sig, &sig_len), CKR_OK);
	ASSERT(sig_len > 0);

	fl->C_Logout(sess);
	fl->C_CloseSession(sess);
	fl->C_Finalize(NULL);
}

TEST(test_ec_sign_via_pkcs11)
{
	create_token_via_assuan("ecp256", "nistp256", "ecpin");

	ASSERT_EQ(fl->C_Initialize(NULL), CKR_OK);

	/* Find the ec slot */
	CK_SLOT_ID slots[64];
	CK_ULONG n = 64;
	fl->C_GetSlotList(CK_TRUE, slots, &n);

	CK_SLOT_ID ec_slot = slots[0];
	for (CK_ULONG i = 0; i < n; i++) {
		CK_TOKEN_INFO ti;
		fl->C_GetTokenInfo(slots[i], &ti);
		if (memcmp(ti.label, "ecp256", 6) == 0) {
			ec_slot = slots[i];
			break;
		}
	}

	CK_SESSION_HANDLE sess = open_session(ec_slot);

	CK_UTF8CHAR pin[] = "ecpin";
	ASSERT_EQ(fl->C_Login(sess, CKU_USER, pin, 5), CKR_OK);

	CK_OBJECT_HANDLE key = find_private_key(sess);

	CK_MECHANISM mech = { CKM_ECDSA, NULL, 0 };
	ASSERT_EQ(fl->C_SignInit(sess, &mech, key), CKR_OK);

	CK_BYTE hash[32];
	memset(hash, 0xCC, sizeof(hash));
	CK_BYTE sig[256];
	CK_ULONG sig_len = sizeof(sig);
	ASSERT_EQ(fl->C_Sign(sess, hash, sizeof(hash), sig, &sig_len), CKR_OK);
	ASSERT(sig_len > 0);

	fl->C_Logout(sess);
	fl->C_CloseSession(sess);
	fl->C_Finalize(NULL);
}

TEST(test_ed25519_visible_via_pkcs11)
{
	create_token_via_assuan("ed25519key", "ed25519", "edpin");

	ASSERT_EQ(fl->C_Initialize(NULL), CKR_OK);

	/* Ed25519 tokens must now appear as PKCS#11 slots. */
	CK_SLOT_ID slots[64];
	CK_ULONG n = 64;
	fl->C_GetSlotList(CK_TRUE, slots, &n);

	int seen = 0;
	for (CK_ULONG i = 0; i < n; i++) {
		CK_TOKEN_INFO ti;
		fl->C_GetTokenInfo(slots[i], &ti);
		if (memcmp(ti.label, "ed25519key", 10) == 0)
			seen = 1;
	}
	ASSERT(seen == 1);

	fl->C_Finalize(NULL);
}

TEST(test_ed25519_key_attributes)
{
	create_token_via_assuan("ed_attrs", "ed25519", "edpin");

	ASSERT_EQ(fl->C_Initialize(NULL), CKR_OK);

	CK_SLOT_ID slots[64];
	CK_ULONG n = 64;
	fl->C_GetSlotList(CK_TRUE, slots, &n);
	CK_SLOT_ID ed_slot = slots[0];
	for (CK_ULONG i = 0; i < n; i++) {
		CK_TOKEN_INFO ti;
		fl->C_GetTokenInfo(slots[i], &ti);
		if (memcmp(ti.label, "ed_attrs", 8) == 0) {
			ed_slot = slots[i];
			break;
		}
	}

	CK_SESSION_HANDLE sess = open_session(ed_slot);

	CK_OBJECT_CLASS cls = CKO_PUBLIC_KEY;
	CK_ATTRIBUTE tmpl[] = { {CKA_CLASS, &cls, sizeof(cls)} };
	ASSERT_EQ(fl->C_FindObjectsInit(sess, tmpl, 1), CKR_OK);
	CK_OBJECT_HANDLE obj;
	CK_ULONG found;
	ASSERT_EQ(fl->C_FindObjects(sess, &obj, 1, &found), CKR_OK);
	ASSERT_EQ(found, (CK_ULONG) 1);
	fl->C_FindObjectsFinal(sess);

	/* Key type must be CKK_EC_EDWARDS. */
	CK_KEY_TYPE kt = 0;
	CK_ATTRIBUTE kt_attr = { CKA_KEY_TYPE, &kt, sizeof(kt) };
	ASSERT_EQ(fl->C_GetAttributeValue(sess, obj, &kt_attr, 1), CKR_OK);
	ASSERT(kt == CKK_EC_EDWARDS);

	/* CKA_EC_PARAMS must be the Ed25519 OID 1.3.101.112. */
	CK_BYTE params[16];
	CK_ATTRIBUTE p_attr = { CKA_EC_PARAMS, params, sizeof(params) };
	ASSERT_EQ(fl->C_GetAttributeValue(sess, obj, &p_attr, 1), CKR_OK);
	static const CK_BYTE ed_oid[] = { 0x06, 0x03, 0x2b, 0x65, 0x70 };
	ASSERT_EQ(p_attr.ulValueLen, (CK_ULONG) sizeof(ed_oid));
	ASSERT(memcmp(params, ed_oid, sizeof(ed_oid)) == 0);

	/* CKA_EC_POINT must be 0x04 0x20 || 32-byte pubkey. */
	CK_BYTE pt[64];
	CK_ATTRIBUTE pt_attr = { CKA_EC_POINT, pt, sizeof(pt) };
	ASSERT_EQ(fl->C_GetAttributeValue(sess, obj, &pt_attr, 1), CKR_OK);
	ASSERT_EQ(pt_attr.ulValueLen, (CK_ULONG) 34);
	ASSERT(pt[0] == 0x04 && pt[1] == 0x20);

	fl->C_CloseSession(sess);
	fl->C_Finalize(NULL);
}

/*
 * Regression test for the imported-Ed25519 CKA_EC_POINT bug: reliquary-tool
 * import-ssh stores the Ed25519 public point as q = 0x40 || A (gcrypt's
 * convention -- see build_ed25519() in src/tools/sshkey.c), whereas a
 * GENKEY'd Ed25519 key happens to come out with a bare 32-byte q. If the
 * CKA_EC_POINT handler wraps q verbatim, an imported key's OCTET STRING ends
 * up 35 bytes ("04 21 40 || <32 bytes>") instead of the 34 bytes OpenSSH's
 * PKCS#11 EdDSA reader requires ("04 20 || <32 bytes>"), and
 * "ssh-keygen -D" fails with "invalid octet str". This test imports a real
 * OpenSSH Ed25519 key via reliquary-tool and reads CKA_EC_POINT directly
 * through the module, so it reproduces the bug without needing OpenSSH's
 * own Ed25519-over-PKCS#11 support (added in OpenSSH 10.1).
 */
TEST(test_ed25519_imported_key_ec_point)
{
	char key_dir[] = "/tmp/test_p11int_edkey_XXXXXX";
	ASSERT_NOT_NULL(mkdtemp(key_dir));

	char keyfile[600];
	snprintf(keyfile, sizeof(keyfile), "%s/id_ed25519", key_dir);
	char gen_cmd[900];
	snprintf(gen_cmd, sizeof(gen_cmd),
		 "ssh-keygen -q -t ed25519 -N '' -C '' -f '%s'", keyfile);
	ASSERT_EQ(system(gen_cmd), 0);

	const char *label = "ed_import";
	const char *pin = "edimportpin";

	char create_stdin[128];
	snprintf(create_stdin, sizeof(create_stdin), "adminpin\n%s\n%s\n",
		 pin, pin);
	char *create_argv[] =
	    { tool_path, "create", (char *)label, NULL };
	run_tool(create_argv, create_stdin);

	char import_stdin[128];
	snprintf(import_stdin, sizeof(import_stdin), "%s\n", pin);
	char *import_argv[] =
	    { tool_path, "import-ssh", (char *)label, "auth", keyfile, NULL };
	run_tool(import_argv, import_stdin);

	char rm_cmd[700];
	snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf '%s'", key_dir);
	ASSERT_EQ(system(rm_cmd), 0);

	ASSERT_EQ(fl->C_Initialize(NULL), CKR_OK);

	CK_SLOT_ID slots[64];
	CK_ULONG n = 64;
	fl->C_GetSlotList(CK_TRUE, slots, &n);
	CK_SLOT_ID ed_slot = slots[0];
	int found_slot = 0;
	for (CK_ULONG i = 0; i < n; i++) {
		CK_TOKEN_INFO ti;
		fl->C_GetTokenInfo(slots[i], &ti);
		if (memcmp(ti.label, label, strlen(label)) == 0) {
			ed_slot = slots[i];
			found_slot = 1;
			break;
		}
	}
	ASSERT(found_slot);

	CK_SESSION_HANDLE sess = open_session(ed_slot);

	CK_OBJECT_CLASS cls = CKO_PUBLIC_KEY;
	CK_ATTRIBUTE tmpl[] = { {CKA_CLASS, &cls, sizeof(cls)} };
	ASSERT_EQ(fl->C_FindObjectsInit(sess, tmpl, 1), CKR_OK);
	CK_OBJECT_HANDLE obj;
	CK_ULONG found;
	ASSERT_EQ(fl->C_FindObjects(sess, &obj, 1, &found), CKR_OK);
	ASSERT_EQ(found, (CK_ULONG) 1);
	fl->C_FindObjectsFinal(sess);

	/* This is the assertion that catches the bug: a buggy module returns
	 * a 35-byte OCTET STRING ("04 21 40 || <32 bytes>"); the fix must
	 * yield exactly 34 bytes ("04 20 || <32 bytes>"). */
	CK_BYTE pt[64];
	CK_ATTRIBUTE pt_attr = { CKA_EC_POINT, pt, sizeof(pt) };
	ASSERT_EQ(fl->C_GetAttributeValue(sess, obj, &pt_attr, 1), CKR_OK);
	ASSERT_EQ(pt_attr.ulValueLen, (CK_ULONG) 34);
	ASSERT(pt[0] == 0x04 && pt[1] == 0x20);

	fl->C_CloseSession(sess);
	fl->C_Finalize(NULL);
}

TEST(test_wrong_pin_via_pkcs11)
{
	ASSERT_EQ(fl->C_Initialize(NULL), CKR_OK);

	CK_SLOT_ID slot = get_first_slot();
	CK_SESSION_HANDLE sess = open_session(slot);

	CK_UTF8CHAR bad[] = "wrongpin";
	ASSERT_EQ(fl->C_Login(sess, CKU_USER, bad, 8), CKR_PIN_INCORRECT);

	fl->C_CloseSession(sess);
	fl->C_Finalize(NULL);
}

TEST(test_sign_without_login)
{
	ASSERT_EQ(fl->C_Initialize(NULL), CKR_OK);

	CK_SLOT_ID slot = get_first_slot();
	CK_SESSION_HANDLE sess = open_session(slot);

	/* Find key object (should exist) */
	CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE tmpl[] = { {CKA_CLASS, &cls, sizeof(cls)}
	};
	ASSERT_EQ(fl->C_FindObjectsInit(sess, tmpl, 1), CKR_OK);
	CK_OBJECT_HANDLE obj;
	CK_ULONG found;
	fl->C_FindObjects(sess, &obj, 1, &found);
	fl->C_FindObjectsFinal(sess);

	if (found > 0) {
		CK_MECHANISM mech = { CKM_RSA_PKCS, NULL, 0 };
		/* SignInit may succeed (lazy check), but Sign must fail */
		fl->C_SignInit(sess, &mech, obj);
		CK_BYTE data[32];
		memset(data, 0xAA, sizeof(data));
		CK_BYTE sig[512];
		CK_ULONG sig_len = sizeof(sig);
		CK_RV rv = fl->C_Sign(sess, data, sizeof(data), sig, &sig_len);
		ASSERT_NEQ(rv, CKR_OK);
	}

	fl->C_CloseSession(sess);
	fl->C_Finalize(NULL);
}

TEST(test_rsa_key_attributes)
{
	ASSERT_EQ(fl->C_Initialize(NULL), CKR_OK);

	/* Find the RSA slot (not necessarily slot 0) */
	CK_SLOT_ID slots[64];
	CK_ULONG n = 64;
	fl->C_GetSlotList(CK_TRUE, slots, &n);
	CK_SLOT_ID rsa_slot = slots[0];
	for (CK_ULONG i = 0; i < n; i++) {
		CK_TOKEN_INFO ti;
		fl->C_GetTokenInfo(slots[i], &ti);
		if (memcmp(ti.label, "rsa2k", 5) == 0) {
			rsa_slot = slots[i];
			break;
		}
	}
	CK_SESSION_HANDLE sess = open_session(rsa_slot);

	/* Find public key object */
	CK_OBJECT_CLASS cls = CKO_PUBLIC_KEY;
	CK_ATTRIBUTE tmpl[] = { {CKA_CLASS, &cls, sizeof(cls)}
	};
	ASSERT_EQ(fl->C_FindObjectsInit(sess, tmpl, 1), CKR_OK);
	CK_OBJECT_HANDLE obj;
	CK_ULONG found;
	ASSERT_EQ(fl->C_FindObjects(sess, &obj, 1, &found), CKR_OK);
	ASSERT_EQ(found, (CK_ULONG) 1);
	fl->C_FindObjectsFinal(sess);

	/* Query modulus size */
	CK_ATTRIBUTE mod_attr = { CKA_MODULUS, NULL, 0 };
	ASSERT_EQ(fl->C_GetAttributeValue(sess, obj, &mod_attr, 1), CKR_OK);
	ASSERT(mod_attr.ulValueLen >= 256);	/* RSA-2048 = 256 bytes */

	/* Fetch modulus */
	CK_BYTE mod_buf[512];
	mod_attr.pValue = mod_buf;
	mod_attr.ulValueLen = sizeof(mod_buf);
	ASSERT_EQ(fl->C_GetAttributeValue(sess, obj, &mod_attr, 1), CKR_OK);
	ASSERT(mod_attr.ulValueLen >= 256);

	/* Query public exponent */
	CK_ATTRIBUTE exp_attr = { CKA_PUBLIC_EXPONENT, NULL, 0 };
	ASSERT_EQ(fl->C_GetAttributeValue(sess, obj, &exp_attr, 1), CKR_OK);
	ASSERT(exp_attr.ulValueLen > 0);

	fl->C_CloseSession(sess);
	fl->C_Finalize(NULL);
}

TEST(test_ec_key_attributes)
{
	ASSERT_EQ(fl->C_Initialize(NULL), CKR_OK);

	/* Find the ec slot */
	CK_SLOT_ID slots[64];
	CK_ULONG n = 64;
	fl->C_GetSlotList(CK_TRUE, slots, &n);

	CK_SLOT_ID ec_slot = slots[0];
	for (CK_ULONG i = 0; i < n; i++) {
		CK_TOKEN_INFO ti;
		fl->C_GetTokenInfo(slots[i], &ti);
		if (memcmp(ti.label, "ecp256", 6) == 0) {
			ec_slot = slots[i];
			break;
		}
	}

	CK_SESSION_HANDLE sess = open_session(ec_slot);

	CK_OBJECT_CLASS cls = CKO_PUBLIC_KEY;
	CK_ATTRIBUTE tmpl[] = { {CKA_CLASS, &cls, sizeof(cls)}
	};
	ASSERT_EQ(fl->C_FindObjectsInit(sess, tmpl, 1), CKR_OK);
	CK_OBJECT_HANDLE obj;
	CK_ULONG found;
	ASSERT_EQ(fl->C_FindObjects(sess, &obj, 1, &found), CKR_OK);
	ASSERT_EQ(found, (CK_ULONG) 1);
	fl->C_FindObjectsFinal(sess);

	/* EC point should be present */
	CK_ATTRIBUTE q_attr = { CKA_EC_POINT, NULL, 0 };
	ASSERT_EQ(fl->C_GetAttributeValue(sess, obj, &q_attr, 1), CKR_OK);
	ASSERT(q_attr.ulValueLen > 0);

	/* EC params (curve OID) should be present */
	CK_ATTRIBUTE params_attr = { CKA_EC_PARAMS, NULL, 0 };
	ASSERT_EQ(fl->C_GetAttributeValue(sess, obj, &params_attr, 1), CKR_OK);
	ASSERT(params_attr.ulValueLen > 0);

	fl->C_CloseSession(sess);
	fl->C_Finalize(NULL);
}

TEST(test_mechanism_list_via_pkcs11)
{
	ASSERT_EQ(fl->C_Initialize(NULL), CKR_OK);

	CK_SLOT_ID slot = get_first_slot();

	CK_ULONG count = 0;
	ASSERT_EQ(fl->C_GetMechanismList(slot, NULL, &count), CKR_OK);
	ASSERT(count > 0);

	CK_MECHANISM_TYPE mechs[16];
	CK_ULONG mc = 16;
	ASSERT_EQ(fl->C_GetMechanismList(slot, mechs, &mc), CKR_OK);
	ASSERT(mc > 0);

	fl->C_Finalize(NULL);
}

TEST(test_find_public_key)
{
	ASSERT_EQ(fl->C_Initialize(NULL), CKR_OK);

	CK_SLOT_ID slot = get_first_slot();
	CK_SESSION_HANDLE sess = open_session(slot);

	CK_OBJECT_CLASS cls = CKO_PUBLIC_KEY;
	CK_ATTRIBUTE tmpl[] = { {CKA_CLASS, &cls, sizeof(cls)}
	};
	ASSERT_EQ(fl->C_FindObjectsInit(sess, tmpl, 1), CKR_OK);

	CK_OBJECT_HANDLE obj;
	CK_ULONG found;
	ASSERT_EQ(fl->C_FindObjects(sess, &obj, 1, &found), CKR_OK);
	ASSERT_EQ(found, (CK_ULONG) 1);
	ASSERT_EQ(fl->C_FindObjectsFinal(sess), CKR_OK);

	fl->C_CloseSession(sess);
	fl->C_Finalize(NULL);
}

TEST(test_session_info)
{
	ASSERT_EQ(fl->C_Initialize(NULL), CKR_OK);

	CK_SLOT_ID slot = get_first_slot();
	CK_SESSION_HANDLE sess = open_session(slot);

	CK_SESSION_INFO info;
	ASSERT_EQ(fl->C_GetSessionInfo(sess, &info), CKR_OK);
	ASSERT_EQ(info.slotID, slot);

	fl->C_CloseSession(sess);
	fl->C_Finalize(NULL);
}

TEST(test_ed25519_mechanism_advertised)
{
	ASSERT_EQ(fl->C_Initialize(NULL), CKR_OK);
	CK_SLOT_ID slot = get_first_slot();

	CK_ULONG count = 0;
	ASSERT_EQ(fl->C_GetMechanismList(slot, NULL, &count), CKR_OK);
	CK_MECHANISM_TYPE mechs[32];
	ASSERT(count <= 32);
	ASSERT_EQ(fl->C_GetMechanismList(slot, mechs, &count), CKR_OK);

	int has_eddsa = 0;
	for (CK_ULONG i = 0; i < count; i++)
		if (mechs[i] == CKM_EDDSA)
			has_eddsa = 1;
	ASSERT(has_eddsa == 1);

	CK_MECHANISM_INFO info;
	ASSERT_EQ(fl->C_GetMechanismInfo(slot, CKM_EDDSA, &info), CKR_OK);
	ASSERT(info.flags & CKF_SIGN);

	fl->C_Finalize(NULL);
}

TEST(test_mechanism_list_agrees_with_daemon)
{
	ASSERT_EQ(fl->C_Initialize(NULL), CKR_OK);
	CK_SLOT_ID slot = get_first_slot();

	CK_ULONG count = 0;
	ASSERT_EQ(fl->C_GetMechanismList(slot, NULL, &count), CKR_OK);
	CK_MECHANISM_TYPE mechs[32];
	ASSERT(count <= 32);
	ASSERT_EQ(fl->C_GetMechanismList(slot, mechs, &count), CKR_OK);

	int has_eddsa = 0;
	for (CK_ULONG i = 0; i < count; i++)
		if (mechs[i] == CKM_EDDSA)
			has_eddsa = 1;
	ASSERT(has_eddsa == 1);

	/* Query the daemon directly (bypassing the stub's cache) and confirm
	   it reports the same authoritative set the stub derived its numeric
	   mechanism list from. The daemon advertises 7 dotted wire tokens;
	   the stub's refresh_mechanisms() dedups sign.rsa-pkcs1 and
	   decrypt.rsa-pkcs1 down to the single numeric CKM_RSA_PKCS, so its
	   C_GetMechanismList count is 6, one less than the daemon's line
	   count -- the daemon is still the single source of truth, the stub
	   just folds the two RSA-PKCS operations into one PKCS#11
	   mechanism. */
	assuan_context_t daemon_ctx;
	ASSERT_EQ(client_connect(&daemon_ctx), 0);

	char *data = NULL;
	size_t len = 0;
	ASSERT_EQ(client_command(daemon_ctx, "GET_MECHANISM_LIST", &data, &len),
		  (gpg_error_t) 0);
	ASSERT_NOT_NULL(data);

	char *buf = malloc(len + 1);
	ASSERT_NOT_NULL(buf);
	memcpy(buf, data, len);
	buf[len] = '\0';
	free(data);

	CK_ULONG daemon_count = 0;
	int daemon_has_eddsa = 0;
	char *line = buf;
	while (line && *line) {
		char *nl = strchr(line, '\n');
		if (nl)
			*nl = '\0';
		if (*line) {
			daemon_count++;
			if (strcmp(line, "sign.eddsa") == 0)
				daemon_has_eddsa = 1;
		}
		line = nl ? nl + 1 : NULL;
	}
	free(buf);

	ASSERT(daemon_has_eddsa == 1);
	/* 7 advertised dotted tokens dedup to 6 numeric mechanisms (see the
	   comment above): the stub's C_GetMechanismList count is exactly one
	   less than the daemon's wire line count. */
	ASSERT_EQ(daemon_count, (CK_ULONG) 7);
	ASSERT_EQ(count, (CK_ULONG) 6);

	client_disconnect(daemon_ctx);
	fl->C_Finalize(NULL);
}

TEST(test_ed25519_sign_via_pkcs11)
{
	create_token_via_assuan("ed_sign", "ed25519", "edpin");

	ASSERT_EQ(fl->C_Initialize(NULL), CKR_OK);

	CK_SLOT_ID slots[64];
	CK_ULONG n = 64;
	fl->C_GetSlotList(CK_TRUE, slots, &n);
	CK_SLOT_ID ed_slot = slots[0];
	for (CK_ULONG i = 0; i < n; i++) {
		CK_TOKEN_INFO ti;
		fl->C_GetTokenInfo(slots[i], &ti);
		if (memcmp(ti.label, "ed_sign", 7) == 0) {
			ed_slot = slots[i];
			break;
		}
	}

	CK_SESSION_HANDLE sess = open_session(ed_slot);

	CK_UTF8CHAR pin[] = "edpin";
	ASSERT_EQ(fl->C_Login(sess, CKU_USER, pin, 5), CKR_OK);

	CK_OBJECT_HANDLE key = find_private_key(sess);

	/* CKM_EDDSA signs the raw message (PureEdDSA), not a hash. */
	CK_MECHANISM mech = { CKM_EDDSA, NULL, 0 };
	ASSERT_EQ(fl->C_SignInit(sess, &mech, key), CKR_OK);

	CK_BYTE msg[32];
	memset(msg, 0xCC, sizeof(msg));
	CK_BYTE sig[128];
	CK_ULONG sig_len = sizeof(sig);
	ASSERT_EQ(fl->C_Sign(sess, msg, sizeof(msg), sig, &sig_len), CKR_OK);
	ASSERT_EQ(sig_len, (CK_ULONG) 64);

	fl->C_Logout(sess);
	fl->C_CloseSession(sess);
	fl->C_Finalize(NULL);
}

TEST(test_distinct_token_serials)
{
	create_token_via_assuan("serial_a", "rsa2048", "serpina");
	create_token_via_assuan("serial_b", "rsa2048", "serpinb");

	ASSERT_EQ(fl->C_Initialize(NULL), CKR_OK);

	CK_SLOT_ID slots[64];
	CK_ULONG n = 64;
	fl->C_GetSlotList(CK_TRUE, slots, &n);

	CK_SLOT_ID slot_a = 0, slot_b = 0;
	int found_a = 0, found_b = 0;
	for (CK_ULONG i = 0; i < n; i++) {
		CK_TOKEN_INFO ti;
		fl->C_GetTokenInfo(slots[i], &ti);
		if (memcmp(ti.label, "serial_a", 8) == 0) {
			slot_a = slots[i];
			found_a = 1;
		} else if (memcmp(ti.label, "serial_b", 8) == 0) {
			slot_b = slots[i];
			found_b = 1;
		}
	}
	ASSERT(found_a);
	ASSERT(found_b);

	CK_TOKEN_INFO ti_a, ti_b;
	ASSERT_EQ(fl->C_GetTokenInfo(slot_a, &ti_a), CKR_OK);
	ASSERT_EQ(fl->C_GetTokenInfo(slot_b, &ti_b), CKR_OK);

	/* No longer both hardcoded "0001" -- each token gets its own serial. */
	ASSERT(memcmp(ti_a.serialNumber, ti_b.serialNumber, 16) != 0);

	/* The PKCS#11 serial must agree with the daemon's own serial attribute
	   -- the same reliquary_format_serial() call backs the PKCS#11
	   GET_ATTRIBUTE serial branch (cmd_session.c) that both this stub and
	   the scd-proxy's SERIALNO translation read, so the faces cannot
	   drift apart. */
	assuan_context_t daemon_ctx;
	ASSERT_EQ(client_connect(&daemon_ctx), 0);
	ASSERT_EQ(client_command_ok(daemon_ctx, "OPEN_SESSION serial_a"), 0);
	char *data = NULL;
	size_t len = 0;
	ASSERT_EQ(client_command(daemon_ctx, "GET_ATTRIBUTE serial", &data,
				 &len), (gpg_error_t) 0);
	ASSERT_NOT_NULL(data);
	ASSERT_EQ(len, (size_t)32);
	/* CK_TOKEN_INFO.serialNumber is a 16-byte field; the stub fills it
	   from the *tail* of the 32-char canonical serial, since the head is
	   a fixed AID prefix shared by every token and the distinguishing
	   %08X is at the end. */
	ASSERT_MEM_EQ(ti_a.serialNumber, data + 16, 16);
	free(data);
	client_command_ok(daemon_ctx, "CLOSE_SESSION");
	client_disconnect(daemon_ctx);

	fl->C_Finalize(NULL);
}

/* Generate a fresh P-256 keypair with libgcrypt and return the raw peer EC
 * point (uncompressed 0x04||X||Y) in *out / *out_len.  Caller frees *out. */
static void
gen_peer_ec_point(unsigned char **out, size_t *out_len)
{
	gcry_sexp_t parms = NULL, kp = NULL, pub = NULL, ecc = NULL, q = NULL;
	ASSERT_EQ(gcry_sexp_build(&parms, NULL,
				  "(genkey(ecc(curve \"NIST P-256\")))"), 0);
	ASSERT_EQ(gcry_pk_genkey(&kp, parms), 0);
	gcry_sexp_release(parms);

	pub = gcry_sexp_find_token(kp, "public-key", 0);
	ASSERT_NOT_NULL(pub);
	ecc = gcry_sexp_find_token(pub, "ecc", 0);
	ASSERT_NOT_NULL(ecc);
	q = gcry_sexp_find_token(ecc, "q", 0);
	ASSERT_NOT_NULL(q);

	size_t qlen = 0;
	const char *qd = gcry_sexp_nth_data(q, 1, &qlen);
	ASSERT_NOT_NULL(qd);
	ASSERT(qlen > 0);

	unsigned char *buf = malloc(qlen);
	ASSERT_NOT_NULL(buf);
	memcpy(buf, qd, qlen);
	*out = buf;
	*out_len = qlen;

	gcry_sexp_release(q);
	gcry_sexp_release(ecc);
	gcry_sexp_release(pub);
	gcry_sexp_release(kp);
}

TEST(test_ecdh_derive_via_pkcs11)
{
	/* ECDH derive is an ENCRYPT-slot operation: only the encrypt slot's EC
	   default allowed set includes CKM_ECDH1_DERIVE (sign/auth are ECDSA
	   only), matching how a real OpenPGP token holds its ECDH key. Generate
	   the base key into the encrypt slot (kslot 1) so enforcement allows it. */
	create_token_via_assuan_slot("ecdh256", "nistp256", "ecdhpin", 1);

	ASSERT_EQ(fl->C_Initialize(NULL), CKR_OK);

	/* Find the ECDH slot by label. */
	CK_SLOT_ID slots[64];
	CK_ULONG n = 64;
	fl->C_GetSlotList(CK_TRUE, slots, &n);
	CK_SLOT_ID ec_slot = slots[0];
	for (CK_ULONG i = 0; i < n; i++) {
		CK_TOKEN_INFO ti;
		fl->C_GetTokenInfo(slots[i], &ti);
		if (memcmp(ti.label, "ecdh256", 7) == 0) {
			ec_slot = slots[i];
			break;
		}
	}

	CK_SESSION_HANDLE sess = open_session(ec_slot);
	CK_UTF8CHAR pin[] = "ecdhpin";
	ASSERT_EQ(fl->C_Login(sess, CKU_USER, pin, 7), CKR_OK);

	CK_OBJECT_HANDLE base = find_private_key(sess);

	/* Fresh peer EC public point. */
	unsigned char *peer = NULL;
	size_t peer_len = 0;
	gen_peer_ec_point(&peer, &peer_len);

	CK_ECDH1_DERIVE_PARAMS params;
	memset(&params, 0, sizeof(params));
	params.kdf = CKD_NULL;
	params.pPublicData = peer;
	params.ulPublicDataLen = (CK_ULONG) peer_len;

	CK_MECHANISM mech = { CKM_ECDH1_DERIVE, &params, sizeof(params) };

	CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
	CK_KEY_TYPE kt = CKK_GENERIC_SECRET;
	CK_BBOOL ck_true = CK_TRUE;
	CK_ATTRIBUTE tmpl[] = {
		{ CKA_CLASS, &cls, sizeof(cls) },
		{ CKA_KEY_TYPE, &kt, sizeof(kt) },
		{ CKA_TOKEN, &ck_true, sizeof(ck_true) },
	};

	CK_OBJECT_HANDLE derived = 0;
	ASSERT_EQ(fl->C_DeriveKey(sess, &mech, base, tmpl, 3, &derived),
		  CKR_OK);
	ASSERT(derived != 0);

	/* CKA_CLASS of the derived object must be CKO_SECRET_KEY. */
	CK_OBJECT_CLASS got_cls = 0;
	CK_ATTRIBUTE cattr = { CKA_CLASS, &got_cls, sizeof(got_cls) };
	ASSERT_EQ(fl->C_GetAttributeValue(sess, derived, &cattr, 1), CKR_OK);
	ASSERT_EQ(got_cls, (CK_OBJECT_CLASS) CKO_SECRET_KEY);

	/* CKA_VALUE must be retrievable and non-empty. */
	CK_ATTRIBUTE vattr = { CKA_VALUE, NULL, 0 };
	ASSERT_EQ(fl->C_GetAttributeValue(sess, derived, &vattr, 1), CKR_OK);
	ASSERT(vattr.ulValueLen > 0);

	CK_BYTE secret[256];
	ASSERT(vattr.ulValueLen <= sizeof(secret));
	vattr.pValue = secret;
	ASSERT_EQ(fl->C_GetAttributeValue(sess, derived, &vattr, 1), CKR_OK);
	ASSERT(vattr.ulValueLen > 0);

	free(peer);
	fl->C_Logout(sess);
	fl->C_CloseSession(sess);
	fl->C_Finalize(NULL);
}

/*
 * Key usage attributes must reflect the OpenPGP slot role (and algorithm),
 * not be blanket-true for every private key.  Regression for the wart where
 * every private key reported CKA_SIGN=TRUE *and* CKA_DECRYPT=TRUE regardless
 * of slot -- which let an encrypt/derive key masquerade as a signing key and
 * let an OpenPGP signing key falsely advertise decrypt.
 */
TEST(test_key_capability_reflects_slot_role)
{
	create_token_via_assuan_slot("capsign", "rsa2048", "1234", 0);	/* sign */
	create_token_via_assuan_slot("capauth", "ed25519", "1234", 2);	/* auth */
	create_token_via_assuan_slot("capenc", "rsa2048", "1234", 1);	/* encr RSA */
	create_token_via_assuan_slot("capder", "nistp256", "1234", 1);	/* encr EC */

	ASSERT_EQ(fl->C_Initialize(NULL), CKR_OK);

	/* sign slot: signs; no decrypt, no derive */
	ASSERT_EQ(priv_key_bool("capsign", CKA_SIGN), CK_TRUE);
	ASSERT_EQ(priv_key_bool("capsign", CKA_DECRYPT), CK_FALSE);
	ASSERT_EQ(priv_key_bool("capsign", CKA_DERIVE), CK_FALSE);

	/* auth slot: signs (this is the ssh key); no decrypt */
	ASSERT_EQ(priv_key_bool("capauth", CKA_SIGN), CK_TRUE);
	ASSERT_EQ(priv_key_bool("capauth", CKA_DECRYPT), CK_FALSE);

	/* encrypt slot, RSA: decrypts; no sign, no derive */
	ASSERT_EQ(priv_key_bool("capenc", CKA_SIGN), CK_FALSE);
	ASSERT_EQ(priv_key_bool("capenc", CKA_DECRYPT), CK_TRUE);
	ASSERT_EQ(priv_key_bool("capenc", CKA_DERIVE), CK_FALSE);

	/* encrypt slot, EC: derives (ECDH); no sign, no decrypt */
	ASSERT_EQ(priv_key_bool("capder", CKA_SIGN), CK_FALSE);
	ASSERT_EQ(priv_key_bool("capder", CKA_DECRYPT), CK_FALSE);
	ASSERT_EQ(priv_key_bool("capder", CKA_DERIVE), CK_TRUE);

	fl->C_Finalize(NULL);
}

TEST_MAIN_BEGIN("test_pkcs11_integration")
    start_daemon();
load_pkcs11();
RUN(test_dlopen_and_get_function_list);
RUN(test_init_finalize);
RUN(test_get_info);
RUN(test_slot_enumeration_rsa);
RUN(test_rsa_sign_via_pkcs11);
RUN(test_ec_sign_via_pkcs11);
RUN(test_ed25519_visible_via_pkcs11);
RUN(test_ed25519_key_attributes);
if (have_ssh_keygen())
	RUN(test_ed25519_imported_key_ec_point);
else
	fprintf(stderr,
		"  test_ed25519_imported_key_ec_point ... SKIP (no ssh-keygen)\n");
RUN(test_wrong_pin_via_pkcs11);
RUN(test_sign_without_login);
RUN(test_rsa_key_attributes);
RUN(test_ec_key_attributes);
RUN(test_mechanism_list_via_pkcs11);
RUN(test_find_public_key);
RUN(test_session_info);
RUN(test_ed25519_mechanism_advertised);
RUN(test_mechanism_list_agrees_with_daemon);
RUN(test_ed25519_sign_via_pkcs11);
RUN(test_distinct_token_serials);
RUN(test_ecdh_derive_via_pkcs11);
RUN(test_key_capability_reflects_slot_role);
cleanup();
TEST_MAIN_END
