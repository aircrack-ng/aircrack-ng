/**
 * \file      test-cipher-arcfour.c
 *
 * \brief     The ARCFOUR stream cipher unit-tests
 *
 * \warning   ARCFOUR is considered a weak cipher and its use constitutes a
 *            security risk! We recommend considering stronger ciphers instead!
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
 * ARC4 tests vectors as posted by Eric Rescorla in sep. 1994:
 *
 * http://groups.google.com/group/comp.security.misc/msg/10a300c9d21afca0
 */
static const uint8_t arc4_test_key[3][8]
	= {{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
	   {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
	   {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};

static const uint8_t arc4_test_pt[3][8]
	= {{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
	   {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	   {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};

static const uint8_t arc4_test_ct[3][8]
	= {{0x75, 0xB7, 0x87, 0x80, 0x99, 0xE0, 0xC5, 0x96},
	   {0x74, 0x94, 0xC2, 0xE7, 0x10, 0x4B, 0x08, 0x79},
	   {0xDE, 0x18, 0x89, 0x41, 0xA3, 0x37, 0x5D, 0x3A}};
// clang-format on

int main(int argc, char ** argv)
{
	int i, error = 0;
	uint8_t ibuf[8];
	uint8_t obuf[8];
	Cipher_RC4_KEY ctx;

	(void) argc;

	for (i = 0; i < 3; i++)
	{
		memcpy(ibuf, arc4_test_pt[i], 8);
		Cipher_RC4_set_key(&ctx, 8, arc4_test_key[i]);
		Cipher_RC4(&ctx, 8, ibuf, obuf);
		error |= test(obuf, (uint8_t *) arc4_test_ct[i], 8, argv[0]);
	}

	return error;
}
