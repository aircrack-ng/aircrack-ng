/**
 * \file      test-digest-sha1.c
 *
 * \brief     The SHA-1 message digest unit-tests
 *
 * \warning   SHA-1 is considered a weak message digest and its use constitutes a
 *            security risk! We recommend considering stronger message digests
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
 * FIPS-180-1 test vectors
 */
static const unsigned char sha1_test_buf[3][57] =
{
    { "abc" },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" },
    { "" }
};

static const size_t sha1_test_buflen[3] =
{
    3, 56, 1000
};

static const unsigned char sha1_test_sum[3][20] =
{
    { 0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E,
      0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D },
    { 0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE,
      0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1 },
    { 0x34, 0xAA, 0x97, 0x3C, 0xD4, 0xC4, 0xDA, 0xA4, 0xF6, 0x1E,
      0xEB, 0x2B, 0xDB, 0xAD, 0x27, 0x31, 0x65, 0x34, 0x01, 0x6F }
};
// clang-format on

int main(int argc, char ** argv)
{
	int i, error = 0;
	uint8_t sha1sum[DIGEST_SHA1_MAC_LEN];

	(void) argc;

	for (i = 0; i < 2; i++)
	{
		error |= Digest_SHA1(sha1_test_buf[i], sha1_test_buflen[i], sha1sum);
		error |= test(sha1sum, sha1_test_sum[i], DIGEST_SHA1_MAC_LEN, argv[0]);
	}

	for (i = 0; i < 2; i++)
	{
		error |= Digest_SHA1_Vector(
			1,
			(const uint8_t * []){(uint8_t *) &sha1_test_buf[i]},
			&sha1_test_buflen[i],
			sha1sum);
		error |= test(sha1sum, sha1_test_sum[i], DIGEST_SHA1_MAC_LEN, argv[0]);
	}

	Digest_SHA1_CTX * ctx = Digest_SHA1_Create();
	uint8_t buf[1000];
	size_t buflen = sizeof(buf);

	memset(buf, 'a', buflen);

	error |= Digest_SHA1_Init(ctx);
	for (i = 0; i < 1000; i++)
	{
		error |= Digest_SHA1_Update(ctx, buf, buflen);
	}
	Digest_SHA1_Finish(ctx, sha1sum);

	error |= test(sha1sum, sha1_test_sum[2], DIGEST_SHA1_MAC_LEN, argv[0]);

	Digest_SHA1_Destroy(ctx);

	return error;
}
