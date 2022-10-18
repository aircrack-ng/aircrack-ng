// clang-format off
/**
 * \file      arcfour-gcrypt.c
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

#ifdef USE_GCRYPT

#include <err.h>                                            // warn{,s} err{,x}
#include <gcrypt.h>

#include "aircrack-ng/crypto/arcfour.h"
// clang-format on

void Cipher_RC4_set_key(Cipher_RC4_KEY * h, size_t l, const uint8_t k[static l])
{
	if (gcry_cipher_open(h, GCRY_CIPHER_ARCFOUR, GCRY_CIPHER_MODE_STREAM, 0)
		!= GPG_ERR_NO_ERROR)
		errx(1, "missing ARCFOUR support");
	if (gcry_cipher_setkey(*h, k, l) != GPG_ERR_NO_ERROR)
		errx(1, "unable to set ARCFOUR key");
}

int Cipher_RC4(Cipher_RC4_KEY * h,
			   size_t l,
			   const uint8_t s[static l],
			   uint8_t d[static l])
{
	if (gcry_cipher_encrypt(*h, d, l, s, l) != GPG_ERR_NO_ERROR)
		errx(1, "failed ARCFOUR encryption");

	gcry_cipher_close(*h);

	return (0);
}

#endif
