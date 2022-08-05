// clang-format off
/**
 * \file      sha256-openssl.c
 *
 * \brief     The SHA-256 cryptographic hash function and PRF (IEEE 802.11r)
 *
 * The Secure Hash Algorithm 2 (256-bit) cryptographic hash function is
 * defined in <em>FIPS 180-4: Secure Hash Standard (SHS)</em>.
 *
 * This code uses the OpenSSL EVP high-level interfaces; which heap allocate!
 *
 * See: https://github.com/openssl/openssl/issues/7219
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
#include <openssl/evp.h>

#include <aircrack-ng/defs.h>
#include <aircrack-ng/crypto/sha256.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
# define EVP_MD_CTX_new EVP_MD_CTX_create
# define EVP_MD_CTX_free EVP_MD_CTX_destroy
#endif
// clang-format on

Digest_SHA256_CTX * Digest_SHA256_Create(void) { return EVP_MD_CTX_new(); }

void Digest_SHA256_Destroy(Digest_SHA256_CTX * ctx)
{
	if (ctx) EVP_MD_CTX_free(ctx);
}

void Digest_SHA256_Clone(Digest_SHA256_CTX ** dst,
						 const Digest_SHA256_CTX * src)
{
	ENSURE(src != NULL);
	ENSURE(dst != NULL);

	(void) EVP_MD_CTX_copy(*dst, src);
}

int Digest_SHA256_Init(Digest_SHA256_CTX * ctx)
{
	if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL))
		return (-1);
	else
		return (0);
}

int Digest_SHA256_Update(Digest_SHA256_CTX * ctx,
						 const uint8_t * input,
						 size_t ilen)
{
	if (!EVP_DigestUpdate(ctx, input, ilen))
		return (-1);
	else
		return (0);
}

int Digest_SHA256_Finish(Digest_SHA256_CTX * ctx,
						 uint8_t output[static DIGEST_SHA256_MAC_LEN])
{
	unsigned int ilen;

	if (!EVP_DigestFinal_ex(ctx, output, &ilen)) return (-1);

	if (ilen != (unsigned int) DIGEST_SHA256_MAC_LEN)
		return (-1);
	else
		return (0);
}

int Digest_SHA256(const uint8_t * input,
				  size_t ilen,
				  uint8_t output[static DIGEST_SHA256_MAC_LEN])
{
	int ret;
	Digest_SHA256_CTX * ctx = NULL;

	if ((ctx = Digest_SHA256_Create()) == NULL)
		errx(1, "Digest_SHA256_Create() failed");
	else if ((ret = Digest_SHA256_Init(ctx)) != 0)
		errx(1, "Digest_SHA256_Init() failed");
	else if ((ret = Digest_SHA256_Update(ctx, input, ilen)) != 0)
		errx(1, "Digest_SHA256_Update() failed");
	else if ((ret = Digest_SHA256_Finish(ctx, output)) != 0)
		errx(1, "Digest_SHA256_Finish() failed");

	Digest_SHA256_Destroy(ctx);

	return (ret);
}
