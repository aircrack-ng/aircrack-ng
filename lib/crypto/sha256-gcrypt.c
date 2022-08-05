// clang-format off
/**
 * \file      sha256-gcrypt.c
 *
 * \brief     The SHA-256 cryptographic hash function and PRF (IEEE 802.11r)
 *
 * The Secure Hash Algorithm 2 (256-bit) cryptographic hash function is
 * defined in <em>FIPS 180-4: Secure Hash Standard (SHS)</em>.
 *
 * \ingroup
 * \cond
 ******************************************************************************
 *
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
#include "aircrack-ng/crypto/crypto.h"
// clang-format on

#ifdef USE_GCRYPT

// clang-format off
#ifndef GCRYPT_WITH_SHA256
# error "Wrong module included for SHA-2-256 with Gcrypt."
#endif
// clang-format on

Digest_SHA256_CTX * Digest_SHA256_Create(void)
{
	return calloc(1, sizeof(Digest_SHA256_CTX));
}

void Digest_SHA256_Destroy(Digest_SHA256_CTX * ctx)
{
	REQUIRE(ctx != NULL);

	free(ctx);
}

void Digest_SHA256_Clone(Digest_SHA256_CTX ** dst,
						 const Digest_SHA256_CTX * src)
{
	REQUIRE(src != NULL);
	REQUIRE(dst != NULL);

	if (gcry_md_copy(*dst, *src) != GPG_ERR_NO_ERROR)
		errx(1, "Failed to copy SHA-1");
}

int Digest_SHA256_Init(Digest_SHA256_CTX * ctx)
{
	REQUIRE(ctx != NULL);

	if (gcry_md_open(ctx, GCRY_MD_SHA256, 0) != GPG_ERR_NO_ERROR)
		errx(1, "Failed to open SHA-2-256");

	return (0);
}

int Digest_SHA256_Update(Digest_SHA256_CTX * ctx,
						 const uint8_t * input,
						 size_t ilen)
{
	gcry_md_write(*ctx, input, ilen);

	return (0);
}

int Digest_SHA256_Finish(Digest_SHA256_CTX * ctx,
						 uint8_t output[static DIGEST_SHA256_MAC_LEN])
{
	unsigned int dlen = gcry_md_get_algo_dlen(gcry_md_get_algo(*ctx));
	unsigned char * dgst = gcry_md_read(*ctx, GCRY_MD_SHA256);

	if (!dgst) return (-1);

	memcpy(output, dgst, dlen);
	gcry_md_close(*ctx);

	return (0);
}

int Digest_SHA256(const uint8_t * input,
				  size_t ilen,
				  uint8_t output[static DIGEST_SHA256_MAC_LEN])
{
	int ret = -1;
	gcry_md_hd_t ctx;

	memset(&ctx, 0, sizeof(ctx));

	if ((ret = Digest_SHA256_Init(&ctx)) != 0)
		errx(1, "Digest_SHA256_Init failed");
	else if ((ret = Digest_SHA256_Update(&ctx, input, ilen)) != 0)
		errx(1, "Digest_SHA256_Update failed");
	else if ((ret = Digest_SHA256_Finish(&ctx, output)) != 0)
		errx(1, "Digest_SHA256_Finish failed");

	return (ret);
}

#endif
