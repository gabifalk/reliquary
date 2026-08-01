/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "testutil.h"
#include "crypto.h"
#include <string.h>

TEST(test_init)
{
	ASSERT_EQ(crypto_init(), 0);
}

TEST(test_random_fills_buffer)
{
	unsigned char buf[32];
	memset(buf, 0, sizeof(buf));
	ASSERT_EQ(crypto_random(buf, sizeof(buf)), 0);
	int all_zero = 1;
	for (size_t i = 0; i < sizeof(buf); i++)
		if (buf[i] != 0) {
			all_zero = 0;
			break;
		}
	ASSERT(!all_zero);
}

TEST(test_random_distinct)
{
	unsigned char a[32], b[32];
	crypto_random(a, sizeof(a));
	crypto_random(b, sizeof(b));
	ASSERT(memcmp(a, b, sizeof(a)) != 0);
}

TEST(test_kdf_deterministic)
{
	const char *pin = "1234";
	unsigned char salt[CRYPTO_KDF_SALT_LEN];
	memset(salt, 0x42, sizeof(salt));

	unsigned char key1[CRYPTO_GCM_KEY_LEN];
	unsigned char key2[CRYPTO_GCM_KEY_LEN];
	ASSERT_EQ(crypto_kdf_derive(pin, 4, salt, key1, sizeof(key1)), 0);
	ASSERT_EQ(crypto_kdf_derive(pin, 4, salt, key2, sizeof(key2)), 0);
	ASSERT_MEM_EQ(key1, key2, sizeof(key1));
}

TEST(test_kdf_different_pin_different_key)
{
	unsigned char salt[CRYPTO_KDF_SALT_LEN];
	memset(salt, 0x42, sizeof(salt));

	unsigned char key1[CRYPTO_GCM_KEY_LEN];
	unsigned char key2[CRYPTO_GCM_KEY_LEN];
	ASSERT_EQ(crypto_kdf_derive("1234", 4, salt, key1, sizeof(key1)), 0);
	ASSERT_EQ(crypto_kdf_derive("5678", 4, salt, key2, sizeof(key2)), 0);
	ASSERT(memcmp(key1, key2, sizeof(key1)) != 0);
}

TEST(test_kdf_different_salt_different_key)
{
	const char *pin = "1234";
	unsigned char salt1[CRYPTO_KDF_SALT_LEN], salt2[CRYPTO_KDF_SALT_LEN];
	memset(salt1, 0x01, sizeof(salt1));
	memset(salt2, 0x02, sizeof(salt2));

	unsigned char key1[CRYPTO_GCM_KEY_LEN];
	unsigned char key2[CRYPTO_GCM_KEY_LEN];
	ASSERT_EQ(crypto_kdf_derive(pin, 4, salt1, key1, sizeof(key1)), 0);
	ASSERT_EQ(crypto_kdf_derive(pin, 4, salt2, key2, sizeof(key2)), 0);
	ASSERT(memcmp(key1, key2, sizeof(key1)) != 0);
}

TEST(test_aead_roundtrip)
{
	unsigned char key[CRYPTO_GCM_KEY_LEN];
	unsigned char nonce[CRYPTO_GCM_NONCE_LEN];
	crypto_random(key, sizeof(key));
	crypto_random(nonce, sizeof(nonce));

	const unsigned char pt[] = "hello reliquary";
	size_t pt_len = sizeof(pt);
	unsigned char ct[sizeof(pt)];
	unsigned char tag[CRYPTO_GCM_TAG_LEN];

	ASSERT_EQ(crypto_aead_encrypt(key, nonce, pt, pt_len, ct, tag), 0);
	ASSERT(memcmp(ct, pt, pt_len) != 0);

	unsigned char decrypted[sizeof(pt)];
	ASSERT_EQ(crypto_aead_decrypt(key, nonce, ct, pt_len, tag, decrypted),
		  0);
	ASSERT_MEM_EQ(decrypted, pt, pt_len);
}

TEST(test_aead_tampered_ciphertext_fails)
{
	unsigned char key[CRYPTO_GCM_KEY_LEN];
	unsigned char nonce[CRYPTO_GCM_NONCE_LEN];
	crypto_random(key, sizeof(key));
	crypto_random(nonce, sizeof(nonce));

	const unsigned char pt[] = "secret data";
	size_t pt_len = sizeof(pt);
	unsigned char ct[sizeof(pt)];
	unsigned char tag[CRYPTO_GCM_TAG_LEN];

	ASSERT_EQ(crypto_aead_encrypt(key, nonce, pt, pt_len, ct, tag), 0);
	ct[0] ^= 0xff;

	unsigned char decrypted[sizeof(pt)];
	ASSERT_EQ(crypto_aead_decrypt(key, nonce, ct, pt_len, tag, decrypted),
		  -1);
}

TEST(test_aead_tampered_tag_fails)
{
	unsigned char key[CRYPTO_GCM_KEY_LEN];
	unsigned char nonce[CRYPTO_GCM_NONCE_LEN];
	crypto_random(key, sizeof(key));
	crypto_random(nonce, sizeof(nonce));

	const unsigned char pt[] = "secret data";
	size_t pt_len = sizeof(pt);
	unsigned char ct[sizeof(pt)];
	unsigned char tag[CRYPTO_GCM_TAG_LEN];

	ASSERT_EQ(crypto_aead_encrypt(key, nonce, pt, pt_len, ct, tag), 0);
	tag[0] ^= 0xff;

	unsigned char decrypted[sizeof(pt)];
	ASSERT_EQ(crypto_aead_decrypt(key, nonce, ct, pt_len, tag, decrypted),
		  -1);
}

TEST(test_aead_wrong_key_fails)
{
	unsigned char key[CRYPTO_GCM_KEY_LEN];
	unsigned char wrong_key[CRYPTO_GCM_KEY_LEN];
	unsigned char nonce[CRYPTO_GCM_NONCE_LEN];
	crypto_random(key, sizeof(key));
	crypto_random(wrong_key, sizeof(wrong_key));
	crypto_random(nonce, sizeof(nonce));

	const unsigned char pt[] = "secret data";
	size_t pt_len = sizeof(pt);
	unsigned char ct[sizeof(pt)];
	unsigned char tag[CRYPTO_GCM_TAG_LEN];

	ASSERT_EQ(crypto_aead_encrypt(key, nonce, pt, pt_len, ct, tag), 0);

	unsigned char decrypted[sizeof(pt)];
	ASSERT_EQ(crypto_aead_decrypt
		  (wrong_key, nonce, ct, pt_len, tag, decrypted), -1);
}

TEST_MAIN_BEGIN("test_crypto")
    RUN(test_init);
RUN(test_random_fills_buffer);
RUN(test_random_distinct);
RUN(test_kdf_deterministic);
RUN(test_kdf_different_pin_different_key);
RUN(test_kdf_different_salt_different_key);
RUN(test_aead_roundtrip);
RUN(test_aead_tampered_ciphertext_fails);
RUN(test_aead_tampered_tag_fails);
RUN(test_aead_wrong_key_fails);
TEST_MAIN_END
