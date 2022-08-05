// clang-format off
/**
 * \file      aes-128-cbc-gcrypt.c
 *
 * \brief     The Advanced Encryption Standard
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stddef.h>                                                   // size_t
#include <stdint.h>                               // [u]int{8,16,32,64}_t types

#include <err.h>                                            // warn{,x} err{,x}
#include <gcrypt.h>

#include "aircrack-ng/defs.h"
#include "aircrack-ng/crypto/aes.h"
// clang-format on

#ifdef USE_GCRYPT

API_EXPORT
Cipher_AES_CTX * Cipher_AES_Encrypt_Init(size_t len, const uint8_t key[static len])
{
	gcry_cipher_hd_t * hd = malloc(sizeof(gcry_cipher_hd_t));

	if (gcry_cipher_open(hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_ECB, 0)
		!= GPG_ERR_NO_ERROR)
	{
		errx(1, "cipher AES-128-CBC open failed");
		return NULL;
	}
	if (gcry_cipher_setkey(*hd, key, len) != GPG_ERR_NO_ERROR)
	{
		errx(1, "AES-128-cbc setkey failed");
		gcry_cipher_close(*hd);
		return NULL;
	}

	return hd;
}

API_EXPORT
int Cipher_AES_Encrypt(Cipher_AES_CTX * ctx,
					   const uint8_t * plain,
					   uint8_t * crypt)
{
	if (gcry_cipher_encrypt(*ctx, crypt, 16, plain, 16) != GPG_ERR_NO_ERROR)
		warnx("Failed to AES encrypt data");
	return 0;
}

API_EXPORT
void Cipher_AES_Encrypt_Deinit(Cipher_AES_CTX * ctx)
{
	gcry_cipher_close(*ctx);
	free(ctx);
}

#endif /* USE_GCRYPT */
