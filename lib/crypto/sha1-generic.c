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
 * \author    The Mbed TLS Contributors
 *
 * \license   BSD-3-CLAUSE
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
#include "aircrack-ng/crypto/sha1.h"
// clang-format on

// clang-format off
/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
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

	**dst = *src;
}

int Digest_SHA1_Init(Digest_SHA1_CTX * ctx)
{
	REQUIRE(ctx != NULL);

	ctx->total[0] = 0;
	ctx->total[1] = 0;

	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xC3D2E1F0;

	return (0);
}

int Digest_Internal_SHA1_Process(Digest_SHA1_CTX * ctx,
								 const uint8_t data[static DIGEST_SHA1_BLK_LEN])
{
	struct
	{
		uint32_t temp, W[16], A, B, C, D, E;
	} local;

	// clang-format off
	GET_UINT32_BE( local.W[ 0], data,  0 );
	GET_UINT32_BE( local.W[ 1], data,  4 );
	GET_UINT32_BE( local.W[ 2], data,  8 );
	GET_UINT32_BE( local.W[ 3], data, 12 );
	GET_UINT32_BE( local.W[ 4], data, 16 );
	GET_UINT32_BE( local.W[ 5], data, 20 );
	GET_UINT32_BE( local.W[ 6], data, 24 );
	GET_UINT32_BE( local.W[ 7], data, 28 );
	GET_UINT32_BE( local.W[ 8], data, 32 );
	GET_UINT32_BE( local.W[ 9], data, 36 );
	GET_UINT32_BE( local.W[10], data, 40 );
	GET_UINT32_BE( local.W[11], data, 44 );
	GET_UINT32_BE( local.W[12], data, 48 );
	GET_UINT32_BE( local.W[13], data, 52 );
	GET_UINT32_BE( local.W[14], data, 56 );
	GET_UINT32_BE( local.W[15], data, 60 );

#define S(x,n) (((x) << (n)) | (((x) & 0xFFFFFFFF) >> (32 - (n))))

#define R(t)                                                    \
    (                                                           \
        local.temp = local.W[( (t) -  3 ) & 0x0F] ^             \
                     local.W[( (t) -  8 ) & 0x0F] ^             \
                     local.W[( (t) - 14 ) & 0x0F] ^             \
                     local.W[  (t)        & 0x0F],              \
        ( local.W[(t) & 0x0F] = S(local.temp,1) )               \
    )

#define P(a,b,c,d,e,x)                                          \
    do                                                          \
    {                                                           \
        (e) += S((a),5) + F((b),(c),(d)) + K + (x);             \
        (b) = S((b),30);                                        \
    } while( 0 )

    local.A = ctx->state[0];
    local.B = ctx->state[1];
    local.C = ctx->state[2];
    local.D = ctx->state[3];
    local.E = ctx->state[4];

#define F(x,y,z) ((z) ^ ((x) & ((y) ^ (z))))
#define K 0x5A827999

	P( local.A, local.B, local.C, local.D, local.E, local.W[0]  );
	P( local.E, local.A, local.B, local.C, local.D, local.W[1]  );
	P( local.D, local.E, local.A, local.B, local.C, local.W[2]  );
	P( local.C, local.D, local.E, local.A, local.B, local.W[3]  );
	P( local.B, local.C, local.D, local.E, local.A, local.W[4]  );
	P( local.A, local.B, local.C, local.D, local.E, local.W[5]  );
	P( local.E, local.A, local.B, local.C, local.D, local.W[6]  );
	P( local.D, local.E, local.A, local.B, local.C, local.W[7]  );
	P( local.C, local.D, local.E, local.A, local.B, local.W[8]  );
	P( local.B, local.C, local.D, local.E, local.A, local.W[9]  );
	P( local.A, local.B, local.C, local.D, local.E, local.W[10] );
	P( local.E, local.A, local.B, local.C, local.D, local.W[11] );
	P( local.D, local.E, local.A, local.B, local.C, local.W[12] );
	P( local.C, local.D, local.E, local.A, local.B, local.W[13] );
	P( local.B, local.C, local.D, local.E, local.A, local.W[14] );
	P( local.A, local.B, local.C, local.D, local.E, local.W[15] );
	P( local.E, local.A, local.B, local.C, local.D, R(16) );
	P( local.D, local.E, local.A, local.B, local.C, R(17) );
	P( local.C, local.D, local.E, local.A, local.B, R(18) );
	P( local.B, local.C, local.D, local.E, local.A, R(19) );

#undef K
#undef F

#define F(x,y,z) ((x) ^ (y) ^ (z))
#define K 0x6ED9EBA1

	P( local.A, local.B, local.C, local.D, local.E, R(20) );
	P( local.E, local.A, local.B, local.C, local.D, R(21) );
	P( local.D, local.E, local.A, local.B, local.C, R(22) );
	P( local.C, local.D, local.E, local.A, local.B, R(23) );
	P( local.B, local.C, local.D, local.E, local.A, R(24) );
	P( local.A, local.B, local.C, local.D, local.E, R(25) );
	P( local.E, local.A, local.B, local.C, local.D, R(26) );
	P( local.D, local.E, local.A, local.B, local.C, R(27) );
	P( local.C, local.D, local.E, local.A, local.B, R(28) );
	P( local.B, local.C, local.D, local.E, local.A, R(29) );
	P( local.A, local.B, local.C, local.D, local.E, R(30) );
	P( local.E, local.A, local.B, local.C, local.D, R(31) );
	P( local.D, local.E, local.A, local.B, local.C, R(32) );
	P( local.C, local.D, local.E, local.A, local.B, R(33) );
	P( local.B, local.C, local.D, local.E, local.A, R(34) );
	P( local.A, local.B, local.C, local.D, local.E, R(35) );
	P( local.E, local.A, local.B, local.C, local.D, R(36) );
	P( local.D, local.E, local.A, local.B, local.C, R(37) );
	P( local.C, local.D, local.E, local.A, local.B, R(38) );
	P( local.B, local.C, local.D, local.E, local.A, R(39) );

#undef K
#undef F

#define F(x,y,z) (((x) & (y)) | ((z) & ((x) | (y))))
#define K 0x8F1BBCDC

	P( local.A, local.B, local.C, local.D, local.E, R(40) );
	P( local.E, local.A, local.B, local.C, local.D, R(41) );
	P( local.D, local.E, local.A, local.B, local.C, R(42) );
	P( local.C, local.D, local.E, local.A, local.B, R(43) );
	P( local.B, local.C, local.D, local.E, local.A, R(44) );
	P( local.A, local.B, local.C, local.D, local.E, R(45) );
	P( local.E, local.A, local.B, local.C, local.D, R(46) );
	P( local.D, local.E, local.A, local.B, local.C, R(47) );
	P( local.C, local.D, local.E, local.A, local.B, R(48) );
	P( local.B, local.C, local.D, local.E, local.A, R(49) );
	P( local.A, local.B, local.C, local.D, local.E, R(50) );
	P( local.E, local.A, local.B, local.C, local.D, R(51) );
	P( local.D, local.E, local.A, local.B, local.C, R(52) );
	P( local.C, local.D, local.E, local.A, local.B, R(53) );
	P( local.B, local.C, local.D, local.E, local.A, R(54) );
	P( local.A, local.B, local.C, local.D, local.E, R(55) );
	P( local.E, local.A, local.B, local.C, local.D, R(56) );
	P( local.D, local.E, local.A, local.B, local.C, R(57) );
	P( local.C, local.D, local.E, local.A, local.B, R(58) );
	P( local.B, local.C, local.D, local.E, local.A, R(59) );

#undef K
#undef F

#define F(x,y,z) ((x) ^ (y) ^ (z))
#define K 0xCA62C1D6

	P( local.A, local.B, local.C, local.D, local.E, R(60) );
	P( local.E, local.A, local.B, local.C, local.D, R(61) );
	P( local.D, local.E, local.A, local.B, local.C, R(62) );
	P( local.C, local.D, local.E, local.A, local.B, R(63) );
	P( local.B, local.C, local.D, local.E, local.A, R(64) );
	P( local.A, local.B, local.C, local.D, local.E, R(65) );
	P( local.E, local.A, local.B, local.C, local.D, R(66) );
	P( local.D, local.E, local.A, local.B, local.C, R(67) );
	P( local.C, local.D, local.E, local.A, local.B, R(68) );
	P( local.B, local.C, local.D, local.E, local.A, R(69) );
	P( local.A, local.B, local.C, local.D, local.E, R(70) );
	P( local.E, local.A, local.B, local.C, local.D, R(71) );
	P( local.D, local.E, local.A, local.B, local.C, R(72) );
	P( local.C, local.D, local.E, local.A, local.B, R(73) );
	P( local.B, local.C, local.D, local.E, local.A, R(74) );
	P( local.A, local.B, local.C, local.D, local.E, R(75) );
	P( local.E, local.A, local.B, local.C, local.D, R(76) );
	P( local.D, local.E, local.A, local.B, local.C, R(77) );
	P( local.C, local.D, local.E, local.A, local.B, R(78) );
	P( local.B, local.C, local.D, local.E, local.A, R(79) );

#undef K
#undef F
	// clang-format on

	ctx->state[0] += local.A;
	ctx->state[1] += local.B;
	ctx->state[2] += local.C;
	ctx->state[3] += local.D;
	ctx->state[4] += local.E;

	return (0);
}

int Digest_SHA1_Update(Digest_SHA1_CTX * ctx,
					   const uint8_t * input,
					   size_t ilen)
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
		if ((ret = Digest_Internal_SHA1_Process(ctx, ctx->buffer)) != 0)
			return (ret);

		input += fill;
		ilen -= fill;
		left = 0;
	}

	while (ilen >= 64)
	{
		if ((ret = Digest_Internal_SHA1_Process(ctx, input)) != 0) return (ret);

		input += 64;
		ilen -= 64;
	}

	if (ilen > 0)
	{
		memcpy((void *) (ctx->buffer + left), input, ilen);
	}

	return (0);
}

int Digest_SHA1_Finish(Digest_SHA1_CTX * ctx, uint8_t output[static DIGEST_SHA1_MAC_LEN])
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

		if ((ret = Digest_Internal_SHA1_Process(ctx, ctx->buffer)) != 0)
			return (ret);

		memset(ctx->buffer, 0, 56);
	}

	/* Add message length */
	// clang-format off
	high = ( ctx->total[0] >> 29 )
	     | ( ctx->total[1] <<  3 );
	low  = ( ctx->total[0] <<  3 );
	// clang-format on

	PUT_UINT32_BE(high, ctx->buffer, 56);
	PUT_UINT32_BE(low, ctx->buffer, 60);

	if ((ret = Digest_Internal_SHA1_Process(ctx, ctx->buffer)) != 0)
		return (ret);

	/* Output final state */
	// clang-format off
	PUT_UINT32_BE( ctx->state[0], output,  0 );
	PUT_UINT32_BE( ctx->state[1], output,  4 );
	PUT_UINT32_BE( ctx->state[2], output,  8 );
	PUT_UINT32_BE( ctx->state[3], output, 12 );
	PUT_UINT32_BE( ctx->state[4], output, 16 );
	// clang-format on

	return (0);
}

int Digest_SHA1(const uint8_t * input,
				size_t ilen,
				uint8_t output[static DIGEST_SHA1_MAC_LEN])
{
	int ret = -1;
	Digest_SHA1_CTX ctx;

	memset(&ctx, 0, sizeof(ctx));

	if ((ret = Digest_SHA1_Init(&ctx)) != 0)
		errx(1, "Digest_SHA1_Init() failed");
	else if ((ret = Digest_SHA1_Update(&ctx, input, ilen)) != 0)
		errx(1, "Digest_SHA1_Update() failed");
	else if ((ret = Digest_SHA1_Finish(&ctx, output)) != 0)
		errx(1, "Digest_SHA1_Finish() failed");

	return (ret);
}
