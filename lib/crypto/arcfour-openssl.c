// clang-format off
/**
 * \file      arcfour-openssl.c
 *
 * \brief     The ARCFOUR stream cipher
 *
 * \warning   ARC4 is considered a weak cipher and its use constitutes a
 *            security risk. We recommend considering stronger ciphers instead.
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

#include "aircrack-ng/crypto/crypto.h"
// clang-format on

#ifdef OPENSSL_WITH_ARCFOUR
# if OPENSSL_VERSION_NUMBER >= 0x30000000L

void Cipher_RC4_set_key(Cipher_RC4_KEY * h, size_t l, const uint8_t k[static l])
{
	EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
	if (   !ctx
		|| !EVP_CipherInit_ex(ctx, EVP_rc4(), NULL, NULL, NULL, 1)
		|| !EVP_CIPHER_CTX_set_padding(ctx, 0)
		|| !EVP_CIPHER_CTX_set_key_length(ctx, l)
		|| !EVP_CipherInit_ex(ctx, NULL, NULL, k, NULL, 1))
		errx(1, "An error occurred processing RC4_set_key");
	h = (void *) ctx;
}

int Cipher_RC4(Cipher_RC4_KEY * h,
			   size_t l,
			   const uint8_t s[static l],
			   uint8_t d[static l])
{
	int outlen = l;
	EVP_CIPHER_CTX * ctx = (void *) h;
	return (EVP_CipherUpdate(ctx, d, &outlen, s, l));
}

#endif
#endif
