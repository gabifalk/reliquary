/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "testutil.h"
#include "hex.h"

TEST(test_encode_empty)
{
	char *r = hex_encode(NULL, 0);
	ASSERT_NOT_NULL(r);
	ASSERT_STR_EQ(r, "");
	free(r);
}

TEST(test_encode_basic)
{
	const unsigned char data[] = { 0xde, 0xad, 0xbe, 0xef };
	char *r = hex_encode(data, 4);
	ASSERT_NOT_NULL(r);
	ASSERT_STR_EQ(r, "deadbeef");
	free(r);
}

TEST(test_encode_zeros)
{
	const unsigned char data[] = { 0x00, 0x00, 0x01 };
	char *r = hex_encode(data, 3);
	ASSERT_NOT_NULL(r);
	ASSERT_STR_EQ(r, "000001");
	free(r);
}

TEST(test_decode_basic)
{
	unsigned char out[4];
	size_t out_len;
	ASSERT_EQ(hex_decode("deadbeef", out, sizeof(out), &out_len), 0);
	ASSERT_EQ(out_len, 4);
	const unsigned char expected[] = { 0xde, 0xad, 0xbe, 0xef };
	ASSERT_MEM_EQ(out, expected, 4);
}

TEST(test_decode_uppercase)
{
	unsigned char out[4];
	size_t out_len;
	ASSERT_EQ(hex_decode("DEADBEEF", out, sizeof(out), &out_len), 0);
	ASSERT_EQ(out_len, 4);
}

TEST(test_decode_odd_length_fails)
{
	unsigned char out[4];
	size_t out_len;
	ASSERT_EQ(hex_decode("abc", out, sizeof(out), &out_len), -1);
}

TEST(test_decode_invalid_char_fails)
{
	unsigned char out[4];
	size_t out_len;
	ASSERT_EQ(hex_decode("zzzz", out, sizeof(out), &out_len), -1);
}

TEST(test_decode_buffer_too_small_fails)
{
	unsigned char out[1];
	size_t out_len;
	ASSERT_EQ(hex_decode("aabbccdd", out, sizeof(out), &out_len), -1);
}

TEST(test_roundtrip)
{
	const unsigned char data[] = { 0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff };
	char *hex = hex_encode(data, sizeof(data));
	ASSERT_NOT_NULL(hex);

	unsigned char decoded[6];
	size_t decoded_len;
	ASSERT_EQ(hex_decode(hex, decoded, sizeof(decoded), &decoded_len), 0);
	ASSERT_EQ(decoded_len, sizeof(data));
	ASSERT_MEM_EQ(decoded, data, sizeof(data));
	free(hex);
}

TEST_MAIN_BEGIN("test_hex")
    RUN(test_encode_empty);
RUN(test_encode_basic);
RUN(test_encode_zeros);
RUN(test_decode_basic);
RUN(test_decode_uppercase);
RUN(test_decode_odd_length_fails);
RUN(test_decode_invalid_char_fails);
RUN(test_decode_buffer_too_small_fails);
RUN(test_roundtrip);
TEST_MAIN_END
