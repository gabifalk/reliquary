/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "testutil.h"
#include "crypto_rsa.h"
#include "crypto.h"
#include "secmem.h"
#include <gcrypt.h>
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
	ASSERT_EQ(crypto_rsa_keygen(2048, &g_key, &g_key_len), 0);
	ASSERT_NOT_NULL(g_key);
	ASSERT_EQ(crypto_rsa_extract_pubkey
		  (g_key, g_key_len, &g_pub, &g_pub_len), 0);
	ASSERT_NOT_NULL(g_pub);
}

TEST(test_keygen)
{
	setup();
	ASSERT(g_key_len > 0);
	ASSERT(g_pub_len > 0);
}

TEST(test_sign_pkcs1_and_verify)
{
	setup();
	unsigned char hash[32];
	crypto_random(hash, sizeof(hash));

	unsigned char *sig = NULL;
	size_t sig_len = 0;
	ASSERT_EQ(crypto_rsa_sign_pkcs1(g_key, g_key_len,
					GCRY_MD_SHA256, hash, sizeof(hash),
					&sig, &sig_len), 0);
	ASSERT_NOT_NULL(sig);
	ASSERT(sig_len > 0);

	ASSERT_EQ(crypto_rsa_verify_pkcs1(g_pub, g_pub_len,
					  GCRY_MD_SHA256, hash, sizeof(hash),
					  sig, sig_len), 0);

	hash[0] ^= 0xff;
	ASSERT_NEQ(crypto_rsa_verify_pkcs1(g_pub, g_pub_len,
					   GCRY_MD_SHA256, hash, sizeof(hash),
					   sig, sig_len), 0);

	free(sig);
}

TEST(test_sign_pss_and_verify)
{
	setup();
	unsigned char hash[32];
	crypto_random(hash, sizeof(hash));

	unsigned char *sig = NULL;
	size_t sig_len = 0;
	ASSERT_EQ(crypto_rsa_sign_pss(g_key, g_key_len,
				      GCRY_MD_SHA256, hash, sizeof(hash), 32,
				      &sig, &sig_len), 0);
	ASSERT_NOT_NULL(sig);

	ASSERT_EQ(crypto_rsa_verify_pss(g_pub, g_pub_len,
					GCRY_MD_SHA256, hash, sizeof(hash), 32,
					sig, sig_len), 0);

	free(sig);
}

TEST(test_encrypt_decrypt_pkcs1)
{
	setup();
	const unsigned char pt[] = "short plaintext";
	size_t pt_len = sizeof(pt);

	unsigned char *ct = NULL;
	size_t ct_len = 0;
	ASSERT_EQ(crypto_rsa_encrypt_pkcs1(g_pub, g_pub_len,
					   pt, pt_len, &ct, &ct_len), 0);
	ASSERT_NOT_NULL(ct);

	unsigned char *dec = NULL;
	size_t dec_len = 0;
	ASSERT_EQ(crypto_rsa_decrypt_pkcs1(g_key, g_key_len,
					   ct, ct_len, &dec, &dec_len), 0);
	ASSERT_EQ(dec_len, pt_len);
	ASSERT_MEM_EQ(dec, pt, pt_len);

	free(ct);
	secure_free(dec, dec_len);
}

TEST(test_encrypt_decrypt_oaep)
{
	setup();
	const unsigned char pt[] = "oaep plaintext";
	size_t pt_len = sizeof(pt);

	unsigned char *ct = NULL;
	size_t ct_len = 0;
	ASSERT_EQ(crypto_rsa_encrypt_oaep(g_pub, g_pub_len,
					  GCRY_MD_SHA256, pt, pt_len, &ct,
					  &ct_len), 0);
	ASSERT_NOT_NULL(ct);

	unsigned char *dec = NULL;
	size_t dec_len = 0;
	ASSERT_EQ(crypto_rsa_decrypt_oaep(g_key, g_key_len,
					  GCRY_MD_SHA256, ct, ct_len, &dec,
					  &dec_len), 0);
	ASSERT_EQ(dec_len, pt_len);
	ASSERT_MEM_EQ(dec, pt, pt_len);

	free(ct);
	secure_free(dec, dec_len);
}

TEST_MAIN_BEGIN("test_crypto_rsa")
    ASSERT_EQ(crypto_init(), 0);
RUN(test_keygen);
RUN(test_sign_pkcs1_and_verify);
RUN(test_sign_pss_and_verify);
RUN(test_encrypt_decrypt_pkcs1);
RUN(test_encrypt_decrypt_oaep);
TEST_MAIN_END
