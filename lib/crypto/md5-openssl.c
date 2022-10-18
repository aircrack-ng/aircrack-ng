// clang-format off
/**
 * \file      md5-openssl.c
 *
 * \brief     The MD5 message digest algorithm (hash function)
 *
 * This code uses the OpenSSL EVP high-level interfaces; which heap allocate!
 * See: https://github.com/openssl/openssl/issues/7219
 *
 * \warning   MD5 is considered a weak digest and its use constitutes a
 *            security risk. We recommend considering stronger digests instead.
 *
 * \author    Joseph Benden <joe@benden.us>
 * \author    Jouni Malinen <j@wl.fi>
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
# include <config.h>
#endif

#include <stddef.h>                                              // {s,ss}ize_t
#include <stdint.h>                                     // [u]int[8,16,32,64]_t

#include <err.h>                                            // warn{,s} err{,x}
#include <openssl/evp.h>

#include "aircrack-ng/defs.h"
#include "aircrack-ng/crypto/md5.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L
# define EVP_MD_CTX_new   EVP_MD_CTX_create
# define EVP_MD_CTX_free  EVP_MD_CTX_destroy
#endif
// clang-format on

Digest_MD5_CTX * Digest_MD5_Create(void) { return EVP_MD_CTX_new(); }

void Digest_MD5_Destroy(Digest_MD5_CTX * ctx) { EVP_MD_CTX_free(ctx); }

int Digest_MD5_Init(Digest_MD5_CTX * ctx)
{
	if (!EVP_DigestInit_ex(ctx, EVP_md5(), NULL))
		return (-1);
	else
		return (0);
}

int Digest_MD5_Update(Digest_MD5_CTX * ctx, const uint8_t * input, size_t ilen)
{
	if (!EVP_DigestUpdate(ctx, input, ilen))
		return (-1);
	else
		return (0);
}

int Digest_MD5_Finish(Digest_MD5_CTX * ctx,
					  uint8_t output[static DIGEST_MD5_MAC_LEN])
{
	unsigned int ilen;

	if (!EVP_DigestFinal_ex(ctx, output, &ilen)) return (-1);

	if (ilen != 16u)
		return (-1);
	else
		return (0);
}

int Digest_MD5(const uint8_t * input,
			   size_t ilen,
			   uint8_t output[static DIGEST_MD5_MAC_LEN])
{
	int ret;
	Digest_MD5_CTX * ctx = NULL;

	if ((ctx = Digest_MD5_Create()) == NULL)
		errx(1, "Digest_MD5_Create() failed");
	else if ((ret = Digest_MD5_Init(ctx)) != 0)
		errx(1, "Digest_MD5_Init() failed");
	else if ((ret = Digest_MD5_Update(ctx, input, ilen)) != 0)
		errx(1, "Digest_MD5_Update() failed");
	else if ((ret = Digest_MD5_Finish(ctx, output)) != 0)
		errx(1, "Digest_MD5_Finish() failed");

	Digest_MD5_Destroy(ctx);

	return (ret);
}
