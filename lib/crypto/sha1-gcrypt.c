// clang-format off
/**
 * \file      sha1-gcrypt.c
 *
 * \brief     The SHA-1 cryptographic hash function
 *
 * The Secure Hash Algorithm 1 (SHA-1) cryptographic hash function is defined
 * in <em>FIPS 180-4: Secure Hash Standard (SHS)</em>.
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
#include <gcrypt.h>

#include "aircrack-ng/defs.h"
#include "aircrack-ng/crypto/sha1.h"
// clang-format on

// clang-format off
#ifndef GCRYPT_WITH_SHA1
# error "Wrong module included for SHA-1 with Gcrypt."
#endif
// clang-format on

Digest_SHA1_CTX * Digest_SHA1_Create(void)
{
	return calloc(1, sizeof(Digest_SHA1_CTX));
}

void Digest_SHA1_Destroy(Digest_SHA1_CTX * ctx)
{
	REQUIRE(ctx != NULL);

	free(ctx);
}

void Digest_SHA1_Clone(Digest_SHA1_CTX ** dst, const Digest_SHA1_CTX * src)
{
	REQUIRE(src != NULL);
	REQUIRE(dst != NULL);

	if (gcry_md_copy(*dst, *src) != GPG_ERR_NO_ERROR)
		errx(1, "Failed to copy SHA-1");
}

int Digest_SHA1_Init(Digest_SHA1_CTX * ctx)
{
	REQUIRE(ctx != NULL);

	if (gcry_md_open(ctx, GCRY_MD_SHA1, 0) != GPG_ERR_NO_ERROR)
		errx(1, "Failed to open SHA-1");

	return (0);
}

int Digest_SHA1_Update(Digest_SHA1_CTX * ctx,
					   const uint8_t * input,
					   size_t ilen)
{
	gcry_md_write(*ctx, input, ilen);

	return (0);
}

int Digest_SHA1_Finish(Digest_SHA1_CTX * ctx,
					   uint8_t output[static DIGEST_SHA1_MAC_LEN])
{
	unsigned int dlen = gcry_md_get_algo_dlen(gcry_md_get_algo(*ctx));
	unsigned char * dgst = gcry_md_read(*ctx, GCRY_MD_SHA1);

	if (!dgst) return (-1);

	memcpy(output, dgst, dlen);
	gcry_md_close(*ctx);

	return (0);
}

int Digest_SHA1(const uint8_t * input,
				size_t ilen,
				uint8_t output[static DIGEST_SHA1_MAC_LEN])
{
	int ret = -1;
	gcry_md_hd_t ctx;

	memset(&ctx, 0, sizeof(ctx));

	if ((ret = Digest_SHA1_Init(&ctx)) != 0)
		errx(1, "Digest_SHA1_Init failed");
	else if ((ret = Digest_SHA1_Update(&ctx, input, ilen)) != 0)
		errx(1, "Digest_SHA1_Update failed");
	else if ((ret = Digest_SHA1_Finish(&ctx, output)) != 0)
		errx(1, "Digest_SHA1_Finish failed");

	return (ret);
}
