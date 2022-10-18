// clang-format off
/**
 * \file      arcfour-generic.c
 *
 * \brief     The ARCFOUR stream cipher
 *
 * \warning   ARC4 is considered a weak cipher and its use constitutes a
 *            security risk. We recommend considering stronger ciphers instead.
 *
 * \author    Joseph Benden <joe@benden.us>
 * \author    The Mbed TLS Contributors
 *
 * \license   Apache-2.0
 *
 * \ingroup
 * \cond
 ******************************************************************************
 *
 *  Portitions are Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************
 * \endcond
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stddef.h>                                              // {s,ss}ize_t
#include <stdint.h>                                     // [u]int[8,16,32,64]_t

#include "aircrack-ng/crypto/arcfour.h"
// clang-format on

#ifdef DEFINE_ARCFOUR_API

void Cipher_RC4_set_key(Cipher_RC4_KEY * ctx,
						size_t keylen,
						const uint8_t key[static keylen])
{
	int i, j, a;
	unsigned int k;
	unsigned char * m;

	ctx->x = 0;
	ctx->y = 0;
	m = ctx->m;

	for (i = 0; i < 256; i++) m[i] = (unsigned char) i;

	j = k = 0;

	for (i = 0; i < 256; i++, k++)
	{
		if (k >= keylen) k = 0;

		a = m[i];
		j = (j + a + key[k]) & 0xFF;
		m[i] = m[j];
		m[j] = (unsigned char) a;
	}
}

int Cipher_RC4(Cipher_RC4_KEY * ctx,
			   size_t length,
			   const uint8_t input[static length],
			   uint8_t output[static length])
{
	int x, y, a, b;
	size_t i;
	unsigned char * m;

	x = ctx->x;
	y = ctx->y;
	m = ctx->m;

	for (i = 0; i < length; i++)
	{
		x = (x + 1) & 0xFF;
		a = m[x];
		y = (y + a) & 0xFF;
		b = m[y];

		m[x] = (unsigned char) b;
		m[y] = (unsigned char) a;

		output[i] = (unsigned char) (input[i] ^ m[(unsigned char) (a + b)]);
	}

	ctx->x = x;
	ctx->y = y;

	return (0);
}

#endif
