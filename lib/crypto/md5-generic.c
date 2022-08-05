// clang-format off
/**
 * \file      md5-generic.c
 *
 * \brief     The MD5 message digest algorithm (hash function)
 *
 * \warning   MD5 is considered a weak digest and its use constitutes a
 *            security risk. We recommend considering stronger digests instead.
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

#include <err.h>                                            // warn{,s} err{,x}

#include "aircrack-ng/defs.h"
#include "aircrack-ng/crypto/md5.h"
// clang-format on

// clang-format off
/*
 * 32-bit integer manipulation macros (little endian)
 */
#ifndef GET_UINT32_LE
#define GET_UINT32_LE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ]       )             \
        | ( (uint32_t) (b)[(i) + 1] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 2] << 16 )             \
        | ( (uint32_t) (b)[(i) + 3] << 24 );            \
}
#endif

#ifndef PUT_UINT32_LE
#define PUT_UINT32_LE(n,b,i)                                    \
{                                                               \
    (b)[(i)    ] = (unsigned char) ( ( (n)       ) & 0xFF );    \
    (b)[(i) + 1] = (unsigned char) ( ( (n) >>  8 ) & 0xFF );    \
    (b)[(i) + 2] = (unsigned char) ( ( (n) >> 16 ) & 0xFF );    \
    (b)[(i) + 3] = (unsigned char) ( ( (n) >> 24 ) & 0xFF );    \
}
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

	ctx->total[0] = 0;
	ctx->total[1] = 0;

	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;

	return (0);
}

int Digest_Internal_MD5_Process(Digest_MD5_CTX * ctx,
							    const uint8_t data[static DIGEST_MD5_BLK_LEN])
{
	struct
	{
		uint32_t X[16], A, B, C, D;
	} local;

	// clang-format off
	GET_UINT32_LE( local.X[ 0], data,  0 );
	GET_UINT32_LE( local.X[ 1], data,  4 );
	GET_UINT32_LE( local.X[ 2], data,  8 );
	GET_UINT32_LE( local.X[ 3], data, 12 );
	GET_UINT32_LE( local.X[ 4], data, 16 );
	GET_UINT32_LE( local.X[ 5], data, 20 );
	GET_UINT32_LE( local.X[ 6], data, 24 );
	GET_UINT32_LE( local.X[ 7], data, 28 );
	GET_UINT32_LE( local.X[ 8], data, 32 );
	GET_UINT32_LE( local.X[ 9], data, 36 );
	GET_UINT32_LE( local.X[10], data, 40 );
	GET_UINT32_LE( local.X[11], data, 44 );
	GET_UINT32_LE( local.X[12], data, 48 );
	GET_UINT32_LE( local.X[13], data, 52 );
	GET_UINT32_LE( local.X[14], data, 56 );
	GET_UINT32_LE( local.X[15], data, 60 );

#define S(x,n)                                                          \
    ( ( (x) << (n) ) | ( ( (x) & 0xFFFFFFFF) >> ( 32 - (n) ) ) )

#define P(a,b,c,d,k,s,t)                                                \
    do                                                                  \
    {                                                                   \
        (a) += F((b),(c),(d)) + local.X[(k)] + (t);                     \
        (a) = S((a),(s)) + (b);                                         \
    } while( 0 )

	local.A = ctx->state[0];
	local.B = ctx->state[1];
	local.C = ctx->state[2];
	local.D = ctx->state[3];

#define F(x,y,z) ((z) ^ ((x) & ((y) ^ (z))))

	P( local.A, local.B, local.C, local.D,  0,  7, 0xD76AA478 );
	P( local.D, local.A, local.B, local.C,  1, 12, 0xE8C7B756 );
	P( local.C, local.D, local.A, local.B,  2, 17, 0x242070DB );
	P( local.B, local.C, local.D, local.A,  3, 22, 0xC1BDCEEE );
	P( local.A, local.B, local.C, local.D,  4,  7, 0xF57C0FAF );
	P( local.D, local.A, local.B, local.C,  5, 12, 0x4787C62A );
	P( local.C, local.D, local.A, local.B,  6, 17, 0xA8304613 );
	P( local.B, local.C, local.D, local.A,  7, 22, 0xFD469501 );
	P( local.A, local.B, local.C, local.D,  8,  7, 0x698098D8 );
	P( local.D, local.A, local.B, local.C,  9, 12, 0x8B44F7AF );
	P( local.C, local.D, local.A, local.B, 10, 17, 0xFFFF5BB1 );
	P( local.B, local.C, local.D, local.A, 11, 22, 0x895CD7BE );
	P( local.A, local.B, local.C, local.D, 12,  7, 0x6B901122 );
	P( local.D, local.A, local.B, local.C, 13, 12, 0xFD987193 );
	P( local.C, local.D, local.A, local.B, 14, 17, 0xA679438E );
	P( local.B, local.C, local.D, local.A, 15, 22, 0x49B40821 );

#undef F

#define F(x,y,z) ((y) ^ ((z) & ((x) ^ (y))))

	P( local.A, local.B, local.C, local.D,  1,  5, 0xF61E2562 );
	P( local.D, local.A, local.B, local.C,  6,  9, 0xC040B340 );
	P( local.C, local.D, local.A, local.B, 11, 14, 0x265E5A51 );
	P( local.B, local.C, local.D, local.A,  0, 20, 0xE9B6C7AA );
	P( local.A, local.B, local.C, local.D,  5,  5, 0xD62F105D );
	P( local.D, local.A, local.B, local.C, 10,  9, 0x02441453 );
	P( local.C, local.D, local.A, local.B, 15, 14, 0xD8A1E681 );
	P( local.B, local.C, local.D, local.A,  4, 20, 0xE7D3FBC8 );
	P( local.A, local.B, local.C, local.D,  9,  5, 0x21E1CDE6 );
	P( local.D, local.A, local.B, local.C, 14,  9, 0xC33707D6 );
	P( local.C, local.D, local.A, local.B,  3, 14, 0xF4D50D87 );
	P( local.B, local.C, local.D, local.A,  8, 20, 0x455A14ED );
	P( local.A, local.B, local.C, local.D, 13,  5, 0xA9E3E905 );
	P( local.D, local.A, local.B, local.C,  2,  9, 0xFCEFA3F8 );
	P( local.C, local.D, local.A, local.B,  7, 14, 0x676F02D9 );
	P( local.B, local.C, local.D, local.A, 12, 20, 0x8D2A4C8A );

#undef F

#define F(x,y,z) ((x) ^ (y) ^ (z))

	P( local.A, local.B, local.C, local.D,  5,  4, 0xFFFA3942 );
	P( local.D, local.A, local.B, local.C,  8, 11, 0x8771F681 );
	P( local.C, local.D, local.A, local.B, 11, 16, 0x6D9D6122 );
	P( local.B, local.C, local.D, local.A, 14, 23, 0xFDE5380C );
	P( local.A, local.B, local.C, local.D,  1,  4, 0xA4BEEA44 );
	P( local.D, local.A, local.B, local.C,  4, 11, 0x4BDECFA9 );
	P( local.C, local.D, local.A, local.B,  7, 16, 0xF6BB4B60 );
	P( local.B, local.C, local.D, local.A, 10, 23, 0xBEBFBC70 );
	P( local.A, local.B, local.C, local.D, 13,  4, 0x289B7EC6 );
	P( local.D, local.A, local.B, local.C,  0, 11, 0xEAA127FA );
	P( local.C, local.D, local.A, local.B,  3, 16, 0xD4EF3085 );
	P( local.B, local.C, local.D, local.A,  6, 23, 0x04881D05 );
	P( local.A, local.B, local.C, local.D,  9,  4, 0xD9D4D039 );
	P( local.D, local.A, local.B, local.C, 12, 11, 0xE6DB99E5 );
	P( local.C, local.D, local.A, local.B, 15, 16, 0x1FA27CF8 );
	P( local.B, local.C, local.D, local.A,  2, 23, 0xC4AC5665 );

#undef F

#define F(x,y,z) ((y) ^ ((x) | ~(z)))

	P( local.A, local.B, local.C, local.D,  0,  6, 0xF4292244 );
	P( local.D, local.A, local.B, local.C,  7, 10, 0x432AFF97 );
	P( local.C, local.D, local.A, local.B, 14, 15, 0xAB9423A7 );
	P( local.B, local.C, local.D, local.A,  5, 21, 0xFC93A039 );
	P( local.A, local.B, local.C, local.D, 12,  6, 0x655B59C3 );
	P( local.D, local.A, local.B, local.C,  3, 10, 0x8F0CCC92 );
	P( local.C, local.D, local.A, local.B, 10, 15, 0xFFEFF47D );
	P( local.B, local.C, local.D, local.A,  1, 21, 0x85845DD1 );
	P( local.A, local.B, local.C, local.D,  8,  6, 0x6FA87E4F );
	P( local.D, local.A, local.B, local.C, 15, 10, 0xFE2CE6E0 );
	P( local.C, local.D, local.A, local.B,  6, 15, 0xA3014314 );
	P( local.B, local.C, local.D, local.A, 13, 21, 0x4E0811A1 );
	P( local.A, local.B, local.C, local.D,  4,  6, 0xF7537E82 );
	P( local.D, local.A, local.B, local.C, 11, 10, 0xBD3AF235 );
	P( local.C, local.D, local.A, local.B,  2, 15, 0x2AD7D2BB );
	P( local.B, local.C, local.D, local.A,  9, 21, 0xEB86D391 );

#undef F
	// clang-format on

	ctx->state[0] += local.A;
	ctx->state[1] += local.B;
	ctx->state[2] += local.C;
	ctx->state[3] += local.D;

	return (0);
}

API_EXPORT
int Digest_MD5_Update(Digest_MD5_CTX * ctx, const uint8_t * input, size_t ilen)
{
	int ret = -1;
	size_t fill;
	uint32_t left;

	if (ilen == 0) return (0);

	left = ctx->total[0] & 0x3F;
	fill = 64 - left;

	ctx->total[0] += (uint32_t) ilen;
	ctx->total[0] &= 0xFFFFFFFF;

	if (ctx->total[0] < (uint32_t) ilen) ctx->total[1]++;

	if (left && ilen >= fill)
	{
		memcpy((void *) (ctx->buffer + left), input, fill);
		if ((ret = Digest_Internal_MD5_Process(ctx, ctx->buffer)) != 0)
			return (ret);

		input += fill;
		ilen -= fill;
		left = 0;
	}

	while (ilen >= 64)
	{
		if ((ret = Digest_Internal_MD5_Process(ctx, input)) != 0) return (ret);

		input += 64;
		ilen -= 64;
	}

	if (ilen > 0)
	{
		memcpy((void *) (ctx->buffer + left), input, ilen);
	}

	return (0);
}

API_EXPORT
int Digest_MD5_Finish(Digest_MD5_CTX * ctx,
					  uint8_t output[static DIGEST_MD5_MAC_LEN])
{
	int ret = -1;
	uint32_t used;
	uint32_t high, low;

	/* Add padding: 0x80 then 0x00 until 8 bytes remain for the length */
	used = ctx->total[0] & 0x3F;

	ctx->buffer[used++] = 0x80;

	if (used <= 56)
	{
		/* Enough room for padding + length in current block */
		memset(ctx->buffer + used, 0, 56 - used);
	}
	else
	{
		/* We'll need an extra block */
		memset(ctx->buffer + used, 0, 64 - used);

		if ((ret = Digest_Internal_MD5_Process(ctx, ctx->buffer)) != 0)
			return (ret);

		memset(ctx->buffer, 0, 56);
	}

	/* Add message length */
	// clang-format off
	high = ( ctx->total[0] >> 29 )
	     | ( ctx->total[1] <<  3 );
	low  = ( ctx->total[0] <<  3 );
	// clang-format on

	PUT_UINT32_LE(low, ctx->buffer, 56);
	PUT_UINT32_LE(high, ctx->buffer, 60);

	if ((ret = Digest_Internal_MD5_Process(ctx, ctx->buffer)) != 0)
		return (ret);

	/* Output final state */
	// clang-format off
	PUT_UINT32_LE( ctx->state[0], output,  0 );
	PUT_UINT32_LE( ctx->state[1], output,  4 );
	PUT_UINT32_LE( ctx->state[2], output,  8 );
	PUT_UINT32_LE( ctx->state[3], output, 12 );
	// clang-format on

	return (0);
}

API_EXPORT
int Digest_MD5(const uint8_t * input,
			   size_t ilen,
			   uint8_t output[static DIGEST_MD5_MAC_LEN])
{
	int ret = -1;
	Digest_MD5_CTX ctx;

	memset(&ctx, 0, sizeof(ctx));

	if ((ret = Digest_MD5_Init(&ctx)) != 0)
		errx(1, "Digest_MD5_Init() failed");
	else if ((ret = Digest_MD5_Update(&ctx, input, ilen)) != 0)
		errx(1, "Digest_MD5_Update() failed");
	else if ((ret = Digest_MD5_Finish(&ctx, output)) != 0)
		errx(1, "Digest_MD5_Finish() failed");

	return (ret);
}
