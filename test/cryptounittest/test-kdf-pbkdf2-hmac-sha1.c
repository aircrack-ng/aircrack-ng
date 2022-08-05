/**
 * \file      test-kdf-pbkdf2-hmac-sha1.c
 *
 * \brief     The PBKDF2 HMAC-SHA-1 unit-tests
 *
 * \warning   SHA-1 is considered a weak message digest and its use constitutes
 *            a security risk! We recommend considering stronger message digests
 *            instead!
 *
 * \copyright 2022 Joseph Benden <joe@benden.us>
 *
 * \license   GPL-2.0-OR-LATER
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>

#include "aircrack-ng/crypto/crypto.h"
#include "tests.h"

// clang-format off
/*
 * RFC 6070 test vectors
 */
struct {
	uint8_t         key[96];
	size_t          key_len;
	uint8_t         data[128];
	size_t          data_len;
	size_t          iterations;
	uint8_t         digest[DIGEST_SHA1_MAC_LEN];
} sha1_tests[] = {
	{
		"password\0",
		8,
		"salt",
		4,
		1,
		{0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71,
		 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06,
		 0x2f, 0xe0, 0x37, 0xa6}
	},
	{
		"password\0",
		8,
		"salt",
		4,
		2,
		{0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c,
		 0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0,
		 0xd8, 0xde, 0x89, 0x57 }
#ifdef EXPENSIVE_TESTS
	},
	{
		"password\0",
		8,
		"salt",
		4,
		4096,
		{0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a,
		 0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0,
		 0x65, 0xa4, 0x29, 0xc1}
	},
	{
		"password\0",
		8,
		"salt",
		4,
		16777216,
		{0xee, 0xfe, 0x3d, 0x61, 0xcd, 0x4d, 0xa4, 0xe4,
		 0xe9, 0x94, 0x5b, 0x3d, 0x6b, 0xa2, 0x15, 0x8c,
		 0x26, 0x34, 0xe9, 0x84}
#endif
	}
};
// clang-format on

STATIC_ASSERT(ArrayCount(sha1_tests) >= 2u, ensure_at_least_2_entries);

int main(int argc, char ** argv)
{
	size_t i;
	int error = 0;
	uint8_t sha1sum[DIGEST_SHA1_MAC_LEN];

	(void) argc;

	for (i = 0; i < ArrayCount(sha1_tests); i++)
	{
		error |= KDF_PBKDF2_SHA1(sha1_tests[i].key,
								 sha1_tests[i].data,
								 sha1_tests[i].data_len,
								 sha1_tests[i].iterations,
								 sha1sum,
								 DIGEST_SHA1_MAC_LEN);
		error |= test(
			sha1sum, sha1_tests[i].digest, DIGEST_SHA1_MAC_LEN, argv[0]);
	}

	return error;
}
