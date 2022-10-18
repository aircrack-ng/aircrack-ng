/**
 * \file      test-digest-md5.c
 *
 * \brief     The MD5 message digest unit-tests
 *
 * \warning   MD5 is considered a weak message digest and its use constitutes a
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
 * RFC 1321 test vectors
 */
static const uint8_t md5_test_buf[7][81] =
{
    { "" },
    { "a" },
    { "abc" },
    { "message digest" },
    { "abcdefghijklmnopqrstuvwxyz" },
    { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" },
    { "12345678901234567890123456789012345678901234567890123456789012345678901234567890" }
};

static const size_t md5_test_buflen[7] =
{
    0, 1, 3, 14, 26, 62, 80
};

static const uint8_t md5_test_sum[7][16] =
{
    { 0xD4, 0x1D, 0x8C, 0xD9, 0x8F, 0x00, 0xB2, 0x04,
      0xE9, 0x80, 0x09, 0x98, 0xEC, 0xF8, 0x42, 0x7E },
    { 0x0C, 0xC1, 0x75, 0xB9, 0xC0, 0xF1, 0xB6, 0xA8,
      0x31, 0xC3, 0x99, 0xE2, 0x69, 0x77, 0x26, 0x61 },
    { 0x90, 0x01, 0x50, 0x98, 0x3C, 0xD2, 0x4F, 0xB0,
      0xD6, 0x96, 0x3F, 0x7D, 0x28, 0xE1, 0x7F, 0x72 },
    { 0xF9, 0x6B, 0x69, 0x7D, 0x7C, 0xB7, 0x93, 0x8D,
      0x52, 0x5A, 0x2F, 0x31, 0xAA, 0xF1, 0x61, 0xD0 },
    { 0xC3, 0xFC, 0xD3, 0xD7, 0x61, 0x92, 0xE4, 0x00,
      0x7D, 0xFB, 0x49, 0x6C, 0xCA, 0x67, 0xE1, 0x3B },
    { 0xD1, 0x74, 0xAB, 0x98, 0xD2, 0x77, 0xD9, 0xF5,
      0xA5, 0x61, 0x1C, 0x2C, 0x9F, 0x41, 0x9D, 0x9F },
    { 0x57, 0xED, 0xF4, 0xA2, 0x2B, 0xE3, 0xC9, 0x55,
      0xAC, 0x49, 0xDA, 0x2E, 0x21, 0x07, 0xB6, 0x7A }
};
// clang-format on

int main(int argc, char ** argv)
{
	int i, error = 0;
	uint8_t md5sum[DIGEST_MD5_MAC_LEN];

	(void) argc;

	for (i = 0; i < 7; i++)
	{
		error |= Digest_MD5(md5_test_buf[i], md5_test_buflen[i], md5sum);
		error |= test(md5sum, md5_test_sum[i], DIGEST_MD5_MAC_LEN, argv[0]);
	}

	for (i = 0; i < 7; i++)
	{
		error |= Digest_MD5_Vector(
			1,
			(const uint8_t * []){(uint8_t *) &md5_test_buf[i]},
			&md5_test_buflen[i],
			md5sum);
		error |= test(md5sum, md5_test_sum[i], DIGEST_MD5_MAC_LEN, argv[0]);
	}

	return error;
}
