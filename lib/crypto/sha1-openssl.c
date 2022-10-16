// clang-format off
/**
 * \file      sha1-openssl.c
 *
 * \brief     The SHA-1 cryptographic hash function
 *
 * The Secure Hash Algorithm 1 (SHA-1) cryptographic hash function is defined
 * in <em>FIPS 180-4: Secure Hash Standard (SHS)</em>.
 *
 * This code uses the OpenSSL EVP high-level interfaces; which heap allocate!
 * See: https://github.com/openssl/openssl/issues/7219
 *
 * \warning   SHA-1 is considered a weak message digest and its use constitutes
 *            a security risk. We recommend considering stronger message
 *            digests instead.
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
#include "aircrack-ng/crypto/sha1.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L
# define EVP_MD_CTX_new   EVP_MD_CTX_create
# define EVP_MD_CTX_free  EVP_MD_CTX_destroy
#endif
// clang-format on

Digest_SHA1_CTX * Digest_SHA1_Create(void) { return EVP_MD_CTX_new(); }

void Digest_SHA1_Destroy(Digest_SHA1_CTX * ctx)
{
	if (ctx) EVP_MD_CTX_free(ctx);
}

void Digest_SHA1_Clone(Digest_SHA1_CTX ** dst, const Digest_SHA1_CTX * src)
{
	REQUIRE(src != NULL);
	REQUIRE(dst != NULL);
	REQUIRE(*dst != NULL);

	(void) EVP_MD_CTX_copy(*dst, src);
}

int Digest_SHA1_Init(Digest_SHA1_CTX * ctx)
{
	if (!EVP_DigestInit_ex(ctx, EVP_sha1(), NULL))
		return (-1);
	else
		return (0);
}

int Digest_SHA1_Update(Digest_SHA1_CTX * ctx,
					   const uint8_t * input,
					   size_t ilen)
{
	if (!EVP_DigestUpdate(ctx, input, ilen))
		return (-1);
	else
		return (0);
}

int Digest_SHA1_Finish(Digest_SHA1_CTX * ctx,
					   uint8_t output[static DIGEST_SHA1_MAC_LEN])
{
	unsigned int ilen;

	if (!EVP_DigestFinal_ex(ctx, output, &ilen)) return (-1);

	if (ilen != (unsigned int) DIGEST_SHA1_MAC_LEN)
		return (-1);
	else
		return (0);
}

int Digest_SHA1(const uint8_t * input,
				size_t ilen,
				uint8_t output[static DIGEST_SHA1_MAC_LEN])
{
	int ret;
	Digest_SHA1_CTX * ctx = NULL;

	if ((ctx = Digest_SHA1_Create()) == NULL)
		errx(1, "Digest_SHA1_Create() failed");
	else if ((ret = Digest_SHA1_Init(ctx)) != 0)
		errx(1, "Digest_SHA1_Init() failed");
	else if ((ret = Digest_SHA1_Update(ctx, input, ilen)) != 0)
		errx(1, "Digest_SHA1_Update() failed");
	else if ((ret = Digest_SHA1_Finish(ctx, output)) != 0)
		errx(1, "Digest_SHA1_Finish() failed");

	Digest_SHA1_Destroy(ctx);

	return (ret);
}
