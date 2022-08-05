// clang-format off
/**
 * \file      md5-gcrypt.c
 *
 * \brief     The MD5 message digest algorithm (hash function)
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
#include <gcrypt.h>

#include "aircrack-ng/defs.h"
#include "aircrack-ng/crypto/md5.h"

#ifndef GCRYPT_WITH_MD5
# error "Wrong module included for MD5 with Gcrypt."
#endif
// clang-format on

API_EXPORT
Digest_MD5_CTX * Digest_MD5_Create(void)
{
	return calloc(1, sizeof(Digest_MD5_CTX));
}

API_EXPORT
void Digest_MD5_Destroy(Digest_MD5_CTX * ctx)
{
	REQUIRE(ctx != NULL);
	free(ctx);
}

API_EXPORT
int Digest_MD5_Init(Digest_MD5_CTX * ctx)
{
	REQUIRE(ctx != NULL);

	if (gcry_md_open(ctx, GCRY_MD_MD5, 0) != GPG_ERR_NO_ERROR)
		errx(1, "Failed to open MD5");

	return (0);
}

API_EXPORT
int Digest_MD5_Update(Digest_MD5_CTX * ctx, const uint8_t * input, size_t ilen)
{
	gcry_md_write(*ctx, input, ilen);

	return (0);
}

API_EXPORT
int Digest_MD5_Finish(Digest_MD5_CTX * ctx,
					  uint8_t output[static DIGEST_MD5_MAC_LEN])
{
	unsigned int dlen = gcry_md_get_algo_dlen(gcry_md_get_algo(*ctx));
	unsigned char * dgst = gcry_md_read(*ctx, GCRY_MD_MD5);

	if (!dgst) return (-1);

	memcpy(output, dgst, dlen);
	gcry_md_close(*ctx);

	return (0);
}

API_EXPORT
int Digest_MD5(const uint8_t * input,
			   size_t ilen,
			   uint8_t output[static DIGEST_MD5_MAC_LEN])
{
	int ret = -1;
	gcry_md_hd_t ctx;

	memset(&ctx, 0, sizeof(ctx));

	if ((ret = Digest_MD5_Init(&ctx)) != 0)
		errx(1, "Digest_MD5_Init() failed");
	else if ((ret = Digest_MD5_Update(&ctx, input, ilen)) != 0)
		errx(1, "Digest_MD5_Update() failed");
	else if ((ret = Digest_MD5_Finish(&ctx, output)) != 0)
		errx(1, "Digest_MD5_Finish() failed");

	return (ret);
}
