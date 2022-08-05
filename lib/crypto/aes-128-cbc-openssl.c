// clang-format off
/**
 * \file      aes-128-cbc-openssl.c
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

#include <openssl/evp.h>                 // OpenSSL high-level interface import
#include <openssl/err.h>                 // ... include error support

#include <aircrack-ng/defs.h>
#include <aircrack-ng/crypto/aes.h>
// clang-format on

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define EVP_MD_CTX_new EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy
#endif

static const EVP_CIPHER * aes_get_evp_cipher(size_t keylen)
{
	switch (keylen)
	{
		case 16:
			return (EVP_aes_128_ecb());
		case 24:
			return (EVP_aes_192_ecb());
		case 32:
			return (EVP_aes_256_ecb());
	}

	return (NULL);
}

API_EXPORT
Cipher_AES_CTX * Cipher_AES_Encrypt_Init(size_t len,
										 const uint8_t key[static len])
{
	EVP_CIPHER_CTX * ctx;
	const EVP_CIPHER * type;

	type = aes_get_evp_cipher(len);
	if (!type)
	{
		warnx("Could not find matching mode for key length %zd.", len);
		return (NULL);
	}

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
	{
		errx(1, "out of memory");
		return (NULL);
	}
	if (EVP_EncryptInit_ex(ctx, type, NULL, key, NULL) != 1)
	{
		warnx("failed to AES encrypt data");
		EVP_CIPHER_CTX_free(ctx);
		return (NULL);
	}
	EVP_CIPHER_CTX_set_padding(ctx, 0);

	return (ctx);
}

API_EXPORT
int Cipher_AES_Encrypt(Cipher_AES_CTX * ctx,
					   const uint8_t * plain,
					   uint8_t * crypt)
{
	int clen = 16;
	if (EVP_EncryptUpdate(ctx, crypt, &clen, plain, 16) != 1)
	{
		warnx("OpenSSL: EVP_EncryptUpdate failed: %s",
			  ERR_error_string(ERR_get_error(), NULL));
		return (-1);
	}
	return (0);
}

API_EXPORT
void Cipher_AES_Encrypt_Deinit(Cipher_AES_CTX * ctx)
{
	uint8_t buf[16];
	int len = sizeof(buf);
	if (EVP_EncryptFinal_ex(ctx, buf, &len) != 1)
	{
		warnx("OpenSSL: EVP_EncryptFinal_ex failed: "
			  "%s",
			  ERR_error_string(ERR_get_error(), NULL));
	}
	if (len != 0)
	{
		warnx("OpenSSL: Unexpected padding length %d "
			  "in AES encrypt",
			  len);
	}
	EVP_CIPHER_CTX_free(ctx);
}
