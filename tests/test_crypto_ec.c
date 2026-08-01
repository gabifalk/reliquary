/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "testutil.h"
#include "crypto_ec.h"
#include "crypto.h"
#include "secmem.h"
#include <gcrypt.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *g_key = NULL;
static size_t g_key_len = 0;
static unsigned char *g_pub = NULL;
static size_t g_pub_len = 0;

static void
setup(void)
{
	if (g_key)
		return;
	ASSERT_EQ(crypto_ec_keygen("NIST P-256", &g_key, &g_key_len), 0);
	ASSERT_NOT_NULL(g_key);
	ASSERT_EQ(crypto_ec_extract_pubkey
		  (g_key, g_key_len, &g_pub, &g_pub_len), 0);
	ASSERT_NOT_NULL(g_pub);
}

TEST(test_keygen)
{
	setup();
	ASSERT(g_key_len > 0);
	ASSERT(g_pub_len > 0);
}

TEST(test_keygen_ed25519)
{
	unsigned char *key = NULL, *pub = NULL;
	size_t key_len, pub_len;
	ASSERT_EQ(crypto_ec_keygen("Ed25519", &key, &key_len), 0);
	ASSERT_EQ(crypto_ec_extract_pubkey(key, key_len, &pub, &pub_len), 0);
	secure_free(key, key_len);
	free(pub);
}

TEST(test_eddsa_sign_verify)
{
	unsigned char *key = NULL, *pub = NULL;
	size_t key_len, pub_len;
	ASSERT_EQ(crypto_ec_keygen("Ed25519", &key, &key_len), 0);
	ASSERT_EQ(crypto_ec_extract_pubkey(key, key_len, &pub, &pub_len), 0);

	unsigned char msg[64];
	crypto_random(msg, sizeof(msg));

	unsigned char *sig = NULL;
	size_t sig_len = 0;
	ASSERT_EQ(crypto_ecdsa_sign(key, key_len,
				    msg, sizeof(msg), &sig, &sig_len), 0);
	ASSERT_NOT_NULL(sig);

	ASSERT_EQ(crypto_ecdsa_verify(pub, pub_len,
				      msg, sizeof(msg), sig, sig_len), 0);

	/* Tampered message should fail */
	msg[0] ^= 0xff;
	ASSERT_NEQ(crypto_ecdsa_verify(pub, pub_len,
				       msg, sizeof(msg), sig, sig_len), 0);

	free(sig);
	secure_free(key, key_len);
	free(pub);
}

/* Rebuild a (sig-val ...) S-expression from a raw r||s signature and verify it,
 * confirming crypto_ecdsa_sign_raw emits a correct fixed-width signature (the
 * form gpg-agent's smartcard path and PKCS#11 CKM_ECDSA expect). */
static int
verify_raw_sig(const char *token, const unsigned char *pub, size_t pub_len,
	       const unsigned char *msg, size_t msg_len,
	       const unsigned char *raw, size_t raw_len)
{
	size_t half = raw_len / 2;
	gcry_sexp_t sx = NULL;
	char fmt[64];
	snprintf(fmt, sizeof(fmt), "(sig-val(%s(r %%b)(s %%b)))", token);
	if (gcry_sexp_build(&sx, NULL, fmt,
			    (int)half, raw, (int)half, raw + half) != 0)
		return -1;
	size_t n = gcry_sexp_sprint(sx, GCRYSEXP_FMT_CANON, NULL, 0);
	unsigned char *buf = malloc(n);
	gcry_sexp_sprint(sx, GCRYSEXP_FMT_CANON, buf, n);
	gcry_sexp_release(sx);
	int rc = crypto_ecdsa_verify(pub, pub_len, msg, msg_len, buf, n);
	free(buf);
	return rc;
}

TEST(test_eddsa_sign_raw)
{
	unsigned char *key = NULL, *pub = NULL;
	size_t key_len, pub_len;
	ASSERT_EQ(crypto_ec_keygen("Ed25519", &key, &key_len), 0);
	ASSERT_EQ(crypto_ec_extract_pubkey(key, key_len, &pub, &pub_len), 0);

	unsigned char msg[64];
	crypto_random(msg, sizeof(msg));

	unsigned char *sig = NULL;
	size_t sig_len = 0;
	ASSERT_EQ(crypto_ecdsa_sign_raw(key, key_len,
					msg, sizeof(msg), &sig, &sig_len), 0);
	ASSERT_NOT_NULL(sig);
	/* Raw form is fixed-width r||s -- even length, no S-expression wrapper. */
	ASSERT_EQ((int)(sig_len % 2), 0);
	ASSERT_NEQ((int)sig[0], '(');

	ASSERT_EQ(verify_raw_sig("eddsa", pub, pub_len,
				 msg, sizeof(msg), sig, sig_len), 0);

	free(sig);
	secure_free(key, key_len);
	free(pub);
}

TEST(test_ecdsa_sign_raw)
{
	setup();
	unsigned char msg[32];
	crypto_random(msg, sizeof(msg));

	unsigned char *sig = NULL;
	size_t sig_len = 0;
	ASSERT_EQ(crypto_ecdsa_sign_raw(g_key, g_key_len,
					msg, sizeof(msg), &sig, &sig_len), 0);
	ASSERT_NOT_NULL(sig);
	ASSERT_EQ((int)(sig_len % 2), 0);

	ASSERT_EQ(verify_raw_sig("ecdsa", g_pub, g_pub_len,
				 msg, sizeof(msg), sig, sig_len), 0);

	free(sig);
}

TEST(test_ecdsa_sign_verify)
{
	setup();
	unsigned char hash[32];
	crypto_random(hash, sizeof(hash));

	unsigned char *sig = NULL;
	size_t sig_len = 0;
	ASSERT_EQ(crypto_ecdsa_sign(g_key, g_key_len,
				    hash, sizeof(hash), &sig, &sig_len), 0);
	ASSERT_NOT_NULL(sig);

	ASSERT_EQ(crypto_ecdsa_verify(g_pub, g_pub_len,
				      hash, sizeof(hash), sig, sig_len), 0);

	/* Tampered hash should fail */
	hash[0] ^= 0xff;
	ASSERT_NEQ(crypto_ecdsa_verify(g_pub, g_pub_len,
				       hash, sizeof(hash), sig, sig_len), 0);

	free(sig);
}

TEST(test_ecdh_derive)
{
	unsigned char *key_a = NULL, *key_b = NULL;
	unsigned char *pub_a = NULL, *pub_b = NULL;
	size_t key_a_len, key_b_len, pub_a_len, pub_b_len;

	ASSERT_EQ(crypto_ec_keygen("NIST P-256", &key_a, &key_a_len), 0);
	ASSERT_EQ(crypto_ec_keygen("NIST P-256", &key_b, &key_b_len), 0);
	ASSERT_EQ(crypto_ec_extract_pubkey
		  (key_a, key_a_len, &pub_a, &pub_a_len), 0);
	ASSERT_EQ(crypto_ec_extract_pubkey
		  (key_b, key_b_len, &pub_b, &pub_b_len), 0);

	unsigned char *secret_ab = NULL, *secret_ba = NULL;
	size_t slen_ab, slen_ba;

	ASSERT_EQ(crypto_ecdh_derive(key_a, key_a_len, pub_b, pub_b_len,
				     &secret_ab, &slen_ab), 0);
	ASSERT_EQ(crypto_ecdh_derive(key_b, key_b_len, pub_a, pub_a_len,
				     &secret_ba, &slen_ba), 0);

	ASSERT_EQ(slen_ab, slen_ba);
	ASSERT_MEM_EQ(secret_ab, secret_ba, slen_ab);

	secure_free(key_a, key_a_len);
	secure_free(key_b, key_b_len);
	free(pub_a);
	free(pub_b);
	secure_free(secret_ab, slen_ab);
	secure_free(secret_ba, slen_ba);
}

/* Strip a keypair down to a private-key-only ECC sexp (as SSH import
 * produces) and confirm crypto_ec_extract_pubkey still recovers the pubkey. */
static void
check_privonly(const char *curve)
{
	unsigned char *key = NULL;
	size_t key_len = 0;
	ASSERT_EQ(crypto_ec_keygen(curve, &key, &key_len), 0);

	gcry_sexp_t kp = NULL;
	ASSERT_EQ(gcry_sexp_new(&kp, key, key_len, 0), 0);
	gcry_sexp_t priv = gcry_sexp_find_token(kp, "private-key", 0);
	ASSERT_NOT_NULL(priv);
	gcry_sexp_release(kp);
	size_t plen = gcry_sexp_sprint(priv, GCRYSEXP_FMT_CANON, NULL, 0);
	unsigned char *pbuf = malloc(plen);
	ASSERT_NOT_NULL(pbuf);
	plen = gcry_sexp_sprint(priv, GCRYSEXP_FMT_CANON, pbuf, plen);
	gcry_sexp_release(priv);

	/* No public-key node present -- this is the case that must now succeed. */
	unsigned char *pub = NULL;
	size_t pub_len = 0;
	ASSERT_EQ(crypto_ec_extract_pubkey(pbuf, plen, &pub, &pub_len), 0);
	ASSERT_NOT_NULL(pub);

	gcry_sexp_t pubsexp = NULL;
	ASSERT_EQ(gcry_sexp_new(&pubsexp, pub, pub_len, 0), 0);
	gcry_sexp_t pk = gcry_sexp_find_token(pubsexp, "public-key", 0);
	ASSERT_NOT_NULL(pk);
	gcry_sexp_release(pk);
	gcry_sexp_release(pubsexp);

	free(pub);
	free(pbuf);
	secure_free(key, key_len);
}

TEST(test_extract_pubkey_privonly_nistp256)
{
	check_privonly("NIST P-256");
}

TEST(test_extract_pubkey_privonly_ed25519)
{
	check_privonly("Ed25519");
}

TEST_MAIN_BEGIN("test_crypto_ec")
    ASSERT_EQ(crypto_init(), 0);
RUN(test_keygen);
RUN(test_keygen_ed25519);
RUN(test_ecdsa_sign_verify);
RUN(test_eddsa_sign_verify);
RUN(test_eddsa_sign_raw);
RUN(test_ecdsa_sign_raw);
RUN(test_ecdh_derive);
RUN(test_extract_pubkey_privonly_nistp256);
RUN(test_extract_pubkey_privonly_ed25519);
TEST_MAIN_END
