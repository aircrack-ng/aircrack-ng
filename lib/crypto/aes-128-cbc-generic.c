// clang-format off
/**
 * \file      aes-128-cbc-generic.c
 *
 * \brief     AES 128-bit with CBC encryption routines
 *
 * \author    Joseph Benden <joe@benden.us>
 * \author    Jouni Malinen <j@w1.fi>
 *
 * \license   BSD-3-CLAUSE
 *
 * \ingroup
 * \cond
 ******************************************************************************
 *
 *  Portions Copyright (c) 2003-2016, Jouni Malinen <j@w1.fi>
 *  SPDX-License-Identifier: BSD-3-CLAUSE
 *
 ******************************************************************************
 * \endcond
 */

#include <config.h>

#include <stddef.h>                                              // {s,ss}ize_t
#include <stdint.h>                                     // [u]int[8,16,32,64]_t

#include <err.h>                                            // err{,x} warn{,x}

#include <aircrack-ng/defs.h>
#include <aircrack-ng/crypto/aes.h>
// clang-format on

API_EXPORT
Cipher_AES_CTX * Cipher_AES_Encrypt_Init(size_t len,
										 const uint8_t key[static len])
{
	REQUIRE(len > 0);
	(void) key;

	return (NULL);
}

API_EXPORT
int Cipher_AES_Encrypt(Cipher_AES_CTX * ctx,
					   const uint8_t * plain,
					   uint8_t * crypt)
{
	REQUIRE(ctx != NULL);
	REQUIRE(plain != NULL);
	REQUIRE(crypt != NULL);
	return (0);
}

API_EXPORT
void Cipher_AES_Encrypt_Deinit(Cipher_AES_CTX * ctx)
{
	REQUIRE(ctx != NULL);
}
