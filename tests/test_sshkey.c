/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _POSIX_C_SOURCE 200809L
#include "testutil.h"
#include "sshkey.h"
#include "crypto.h"
#include <gcrypt.h>
#include <stdlib.h>
#include <stdio.h>

static const char *dir = "/tmp/test_reliquary_sshkey";

static void
setup(void)
{
	char cmd[256];
	snprintf(cmd, sizeof(cmd), "rm -rf %s && mkdir -p %s", dir, dir);
	ASSERT_EQ(system(cmd), 0);
}

static void
cleanup(void)
{
	char cmd[256];
	snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
	ASSERT_EQ(system(cmd), 0);
}

/* Generate an unencrypted OpenSSH key of the given type at dir/name. */
static void
gen_key(const char *name, const char *type, const char *bits)
{
	char cmd[512];
	if (bits)
		snprintf(cmd, sizeof(cmd),
			 "ssh-keygen -q -t %s -b %s -N '' -C '' -f %s/%s",
			 type, bits, dir, name);
	else
		snprintf(cmd, sizeof(cmd),
			 "ssh-keygen -q -t %s -N '' -C '' -f %s/%s",
			 type, dir, name);
	ASSERT_EQ(system(cmd), 0);
}

/* Load dir/name, assert the sexp is a consistent private key, assert algo. */
static void
check_key(const char *name, const char *want_algo)
{
	char path[300];
	snprintf(path, sizeof(path), "%s/%s", dir, name);

	unsigned char *sexp = NULL;
	size_t sexp_len = 0;
	char *algo = NULL;
	ASSERT_EQ(sshkey_load(path, NULL, &sexp, &sexp_len, &algo), 0);
	ASSERT_NOT_NULL(sexp);
	ASSERT(sexp_len > 0);
	ASSERT_NOT_NULL(algo);
	ASSERT_STR_EQ(algo, want_algo);

	gcry_sexp_t s = NULL;
	ASSERT_EQ(gcry_sexp_new(&s, sexp, sexp_len, 0), 0);
	/* testkey verifies the private/public components are consistent --
	 * catches wrong scalars and the RSA p/q/u ordering bug. */
	ASSERT_EQ(gcry_pk_testkey(s), 0);
	gcry_sexp_release(s);

	free(sexp);
	free(algo);
}

TEST(test_load_ed25519)
{
	gen_key("id_ed25519", "ed25519", NULL);
	check_key("id_ed25519", "ed25519");
}

TEST(test_load_rsa2048)
{
	gen_key("id_rsa", "rsa", "2048");
	check_key("id_rsa", "rsa2048");
}

TEST(test_load_ecdsa256)
{
	gen_key("id_ecdsa", "ecdsa", "256");
	check_key("id_ecdsa", "nistp256");
}

TEST(test_load_ecdsa384)
{
	gen_key("id_ecdsa384", "ecdsa", "384");
	check_key("id_ecdsa384", "nistp384");
}

TEST(test_load_ecdsa521)
{
	gen_key("id_ecdsa521", "ecdsa", "521");
	check_key("id_ecdsa521", "nistp521");
}

TEST(test_load_ed25519_encrypted)
{
	char cmd[512];
	snprintf(cmd, sizeof(cmd),
		 "ssh-keygen -q -t ed25519 -N 'sikrit' -C '' -f %s/id_enc", dir);
	ASSERT_EQ(system(cmd), 0);

	char path[300];
	snprintf(path, sizeof(path), "%s/id_enc", dir);

	ASSERT_EQ(sshkey_is_encrypted(path), 1);

	unsigned char *sexp = NULL;
	size_t sexp_len = 0;
	char *algo = NULL;
	ASSERT_EQ(sshkey_load(path, "sikrit", &sexp, &sexp_len, &algo), 0);
	ASSERT_STR_EQ(algo, "ed25519");

	gcry_sexp_t s = NULL;
	ASSERT_EQ(gcry_sexp_new(&s, sexp, sexp_len, 0), 0);
	ASSERT_EQ(gcry_pk_testkey(s), 0);
	gcry_sexp_release(s);

	/* Wrong passphrase must fail cleanly. */
	unsigned char *sexp2 = NULL;
	size_t sl2 = 0;
	char *algo2 = NULL;
	ASSERT_EQ(sshkey_load(path, "wrong", &sexp2, &sl2, &algo2), -1);

	free(sexp);
	free(algo);
}

TEST(test_load_rsa_encrypted)
{
	char cmd[512];
	snprintf(cmd, sizeof(cmd),
		 "ssh-keygen -q -t rsa -b 2048 -N 'sikrit' -C '' -f %s/id_rsa_e",
		 dir);
	ASSERT_EQ(system(cmd), 0);
	char path[300];
	snprintf(path, sizeof(path), "%s/id_rsa_e", dir);
	ASSERT_EQ(sshkey_is_encrypted(path), 1);
	unsigned char *sexp = NULL; size_t sl = 0; char *algo = NULL;
	ASSERT_EQ(sshkey_load(path, "sikrit", &sexp, &sl, &algo), 0);
	ASSERT_STR_EQ(algo, "rsa2048");
	gcry_sexp_t s = NULL;
	ASSERT_EQ(gcry_sexp_new(&s, sexp, sl, 0), 0);
	ASSERT_EQ(gcry_pk_testkey(s), 0);
	gcry_sexp_release(s);
	free(sexp); free(algo);
}

TEST(test_load_ecdsa_encrypted)
{
	char cmd[512];
	snprintf(cmd, sizeof(cmd),
		 "ssh-keygen -q -t ecdsa -b 256 -N 'sikrit' -C '' -f %s/id_ecdsa_e",
		 dir);
	ASSERT_EQ(system(cmd), 0);
	char path[300];
	snprintf(path, sizeof(path), "%s/id_ecdsa_e", dir);
	ASSERT_EQ(sshkey_is_encrypted(path), 1);
	unsigned char *sexp = NULL; size_t sl = 0; char *algo = NULL;
	ASSERT_EQ(sshkey_load(path, "sikrit", &sexp, &sl, &algo), 0);
	ASSERT_STR_EQ(algo, "nistp256");
	gcry_sexp_t s = NULL;
	ASSERT_EQ(gcry_sexp_new(&s, sexp, sl, 0), 0);
	ASSERT_EQ(gcry_pk_testkey(s), 0);
	gcry_sexp_release(s);
	free(sexp); free(algo);
}

int
main(void)
{
	printf("test_sshkey:\n");
	if (system("command -v ssh-keygen >/dev/null 2>&1") != 0) {
		printf("SKIP: ssh-keygen not found\n");
		return 77;
	}
	ASSERT_EQ(crypto_init(), 0);
	setup();
	RUN(test_load_ed25519);
	RUN(test_load_rsa2048);
	RUN(test_load_ecdsa256);
	RUN(test_load_ecdsa384);
	RUN(test_load_ecdsa521);
	RUN(test_load_ed25519_encrypted);
	RUN(test_load_rsa_encrypted);
	RUN(test_load_ecdsa_encrypted);
	cleanup();
	printf("%d/%d passed\n", tu_pass, tu_count);
	return (tu_pass == tu_count) ? 0 : 1;
}
