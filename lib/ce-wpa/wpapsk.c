/*
 * Based on John the Ripper and modified to integrate with aircrack
 *
 * 	John the Ripper copyright and license.
 *
 * John the Ripper password cracker,
 * Copyright (c) 1996-2013 by Solar Designer.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * As a special exception to the GNU General Public License terms,
 * permission is hereby granted to link the code of this program, with or
 * without modification, with any version of the OpenSSL library and/or any
 * version of unRAR, and to distribute such linked combinations.  You must
 * obey the GNU GPL in all respects for all of the code used other than
 * OpenSSL and unRAR.  If you modify this program, you may extend this
 * exception to your version of the program, but you are not obligated to
 * do so.  (In other words, you may release your derived work under pure
 * GNU GPL version 2 or later as published by the FSF.)
 *
 * (This exception from the GNU GPL is not required for the core tree of
 * John the Ripper, but arguably it is required for -jumbo.)
 *
 * 	Relaxed terms for certain components.
 *
 * In addition or alternatively to the license above, many components are
 * available to you under more relaxed terms (most commonly under cut-down
 * BSD license) as specified in the corresponding source files.
 *
 * For more information on John the Ripper licensing please visit:
 *
 * http://www.openwall.com/john/doc/LICENSE.shtml
 *
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz at openwall dot net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Code is based on Aircrack-ng source
 *
 * SSE2 code enhancement, Jim Fougeron, Jan, 2013.
 *   Also removed oSSL code: HMAC(EVP_sha1(), ....), and coded what it does
 * (which is simple), inline.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdint.h>

#include <aircrack-ng/crypto/crypto.h>
#include "aircrack-ng/ce-wpa/simd-intrinsics.h"
#include "aircrack-ng/aircrack-ng.h"
#include "aircrack-ng/ce-wpa/arch.h"
#include "aircrack-ng/ce-wpa/wpapsk.h"
#include "aircrack-ng/ce-wpa/johnswap.h"
#include "aircrack-ng/ce-wpa/memory.h"
#include "aircrack-ng/cpu/simd_cpuid.h"

// #define XDEBUG

#if defined(__INTEL_COMPILER)
#define SIMD_PARA_SHA1 1
#elif defined(__clang__)
#define SIMD_PARA_SHA1 1
#elif defined(__llvm__)
#define SIMD_PARA_SHA1 1
#elif defined(__GNUC__) && GCC_VERSION < 40504 // 4.5.4
#define SIMD_PARA_SHA1 1
#elif !defined(__AVX__) && defined(__GNUC__) && GCC_VERSION > 40700 // 4.7.0
#define SIMD_PARA_SHA1 1
#else
#define SIMD_PARA_SHA1 1
#endif

#ifdef SIMD_CORE
#ifdef SIMD_COEF_32
#define NBKEYS (SIMD_COEF_32 * SIMD_PARA_SHA1)
#ifdef _OPENMP
#include <omp.h>
#endif
#else
#define NBKEYS 1
#ifdef _OPENMP
#include <omp.h>
#endif
#endif
#else
#ifdef MMX_COEF
#define NBKEYS (MMX_COEF * SHA1_SSE_PARA)
#ifdef _OPENMP
#include <omp.h>
#endif
#else
#define NBKEYS 1
#ifdef _OPENMP
#include <omp.h>
#endif
#endif
#endif

#ifndef SIMD_CORE
#undef SIMDSHA1body
#define SIMDSHA1body SSESHA1body
#endif

static char itoa64[64]
	= "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
char atoi64[0x100];

/* for endianity conversion */
#ifdef SIMD_CORE
#define GETPOS(i, index)                                                       \
	((index & (SIMD_COEF_32 - 1)) * 4                                          \
	 + ((i) & (0xffffffff - 3)) * SIMD_COEF_32                                 \
	 + (3 - ((i) &3))                                                          \
	 + (unsigned int) index / SIMD_COEF_32 * SHA_BUF_SIZ * SIMD_COEF_32 * 4)
#else
#define GETPOS(i, index)                                                       \
	(((index) & (MMX_COEF - 1)) * 4 + ((i) & (0xffffffff - 3)) * MMX_COEF      \
	 + (3 - ((i) &3))                                                          \
	 + ((index) >> (MMX_COEF >> 1)) * SHA_BUF_SIZ * MMX_COEF * 4)
#endif

#define BUF_BASE_OFFSET_OF(co, width, index)                                   \
	(((index) / (co)) * (co) * (width) + ((index) & ((co) -1)))
#define BUF_OFFSET_OF(co, width, index, offset)                                \
	(BUF_BASE_OFFSET_OF((co), (width), (index)) + (offset) * (co))
#define SSE_HASH1_PTR_OF(j)                                                    \
	&((uint32_t *)                                                             \
		  t_sse_hash1)[((((j) / SIMD_COEF_32) * SHA_BUF_SIZ) * SIMD_COEF_32)   \
					   + ((j) & (SIMD_COEF_32 - 1))]
#define MMX_HASH1_PTR_OF(j)                                                    \
	&((uint32_t *) t_sse_hash1)[((((j) >> 2) * SHA_BUF_SIZ) << 2)              \
								+ ((j) & (MMX_COEF - 1))]

#ifdef SIMD_CORE
static MAYBE_INLINE void wpapsk_sse(ac_crypto_engine_t * engine,
									int threadid,
									int count,
									const wpapsk_password * in)
{
	int t; // thread count
	int salt_length = engine->essid_length;
	int slen = salt_length + 4;
	int loops = (count + NBKEYS - 1) / NBKEYS;

	unsigned char * sse_hash1 = NULL;
	unsigned char * sse_crypt1 = NULL;
	unsigned char * sse_crypt2 = NULL;
	unsigned char essid[ESSID_LENGTH + 4];

	sse_hash1 = engine->thread_data[threadid]->hash1;
	sse_crypt1 = engine->thread_data[threadid]->crypt1;
	sse_crypt2 = engine->thread_data[threadid]->crypt2;

	memset(essid, 0, sizeof(essid));
	strncpy((char *) essid,
			(const char *) engine->essid,
			(size_t) engine->essid_length);

	for (t = 0; t < loops; t++)
	{
		unsigned int i, k, j;
		union {
			unsigned char c[64];
			uint32_t i[16];
		} buffer[NBKEYS];
		char __dummy[CACHELINE_SIZE];
		union {
			unsigned char c[40]; // only 40 are used
			uint32_t i[10]; // only 8 are used
		} outbuf[NBKEYS];
		char __dummy2[CACHELINE_SIZE];
		SHA_CTX ctx_ipad[NBKEYS];
		SHA_CTX ctx_opad[NBKEYS];

		SHA_CTX sha1_ctx;
		unsigned int *i1, *i2, *o1;
		unsigned char *t_sse_crypt1, *t_sse_crypt2, *t_sse_hash1;

		// All pointers get their offset for this thread here. No further
		// offsetting below.
		t_sse_crypt1 = &sse_crypt1[t * NBKEYS * 20];
		t_sse_crypt2 = &sse_crypt2[t * NBKEYS * 20];
		t_sse_hash1 = &sse_hash1[t * NBKEYS * SHA_BUF_SIZ * 4];
		i1 = (unsigned int *) t_sse_crypt1;
		i2 = (unsigned int *) t_sse_crypt2;
		o1 = (unsigned int *) t_sse_hash1;
		(void) __dummy;
		(void) __dummy2;

		for (j = 0; j < NBKEYS; ++j)
		{
			memcpy(
				buffer[j].c, in[t * NBKEYS + j].v, in[t * NBKEYS + j].length);
			memset(&buffer[j].c[in[t * NBKEYS + j].length],
				   0,
				   64 - in[t * NBKEYS + j].length);
			SHA1_Init(&ctx_ipad[j]);
			SHA1_Init(&ctx_opad[j]);

			for (i = 0; i < 16; i++) buffer[j].i[i] ^= 0x36363636;
			SHA1_Update(&ctx_ipad[j], buffer[j].c, 64);

			for (i = 0; i < 16; i++) buffer[j].i[i] ^= 0x6a6a6a6a;
			SHA1_Update(&ctx_opad[j], buffer[j].c, 64);

#ifdef SIMD_CORE
			i1[BUF_OFFSET_OF(SIMD_COEF_32, 5, j, 0)] = ctx_ipad[j].h0;
			i1[BUF_OFFSET_OF(SIMD_COEF_32, 5, j, 1)] = ctx_ipad[j].h1;
			i1[BUF_OFFSET_OF(SIMD_COEF_32, 5, j, 2)] = ctx_ipad[j].h2;
			i1[BUF_OFFSET_OF(SIMD_COEF_32, 5, j, 3)] = ctx_ipad[j].h3;
			i1[BUF_OFFSET_OF(SIMD_COEF_32, 5, j, 4)] = ctx_ipad[j].h4;

			i2[BUF_OFFSET_OF(SIMD_COEF_32, 5, j, 0)] = ctx_opad[j].h0;
			i2[BUF_OFFSET_OF(SIMD_COEF_32, 5, j, 1)] = ctx_opad[j].h1;
			i2[BUF_OFFSET_OF(SIMD_COEF_32, 5, j, 2)] = ctx_opad[j].h2;
			i2[BUF_OFFSET_OF(SIMD_COEF_32, 5, j, 3)] = ctx_opad[j].h3;
			i2[BUF_OFFSET_OF(SIMD_COEF_32, 5, j, 4)] = ctx_opad[j].h4;
#else
			i1[BUF_OFFSET_OF(MMX_COEF, 5, j, 0)] = ctx_ipad[j].h0;
			i1[BUF_OFFSET_OF(MMX_COEF, 5, j, 1)] = ctx_ipad[j].h1;
			i1[BUF_OFFSET_OF(MMX_COEF, 5, j, 2)] = ctx_ipad[j].h2;
			i1[BUF_OFFSET_OF(MMX_COEF, 5, j, 3)] = ctx_ipad[j].h3;
			i1[BUF_OFFSET_OF(MMX_COEF, 5, j, 4)] = ctx_ipad[j].h4;

			i2[BUF_OFFSET_OF(MMX_COEF, 5, j, 0)] = ctx_opad[j].h0;
			i2[BUF_OFFSET_OF(MMX_COEF, 5, j, 1)] = ctx_opad[j].h1;
			i2[BUF_OFFSET_OF(MMX_COEF, 5, j, 2)] = ctx_opad[j].h2;
			i2[BUF_OFFSET_OF(MMX_COEF, 5, j, 3)] = ctx_opad[j].h3;
			i2[BUF_OFFSET_OF(MMX_COEF, 5, j, 4)] = ctx_opad[j].h4;
#endif

			essid[slen - 1] = 1;
			// This code does the HMAC(EVP_....) call.  We already have essid
			// appended with BE((int)1) so we simply call a single SHA1_Update
			memcpy(&sha1_ctx, &ctx_ipad[j], sizeof(sha1_ctx));
			SHA1_Update(&sha1_ctx, essid, slen);
			SHA1_Final(outbuf[j].c, &sha1_ctx);
			memcpy(&sha1_ctx, &ctx_opad[j], sizeof(sha1_ctx));
			SHA1_Update(&sha1_ctx, outbuf[j].c, SHA_DIGEST_LENGTH);
			SHA1_Final(outbuf[j].c, &sha1_ctx);

// now convert this from flat into COEF buffers. Also, perform the
// 'first' ^= into the crypt buffer.  We are doing that in BE
// format so we will need to 'undo' that in the end.
#ifdef SIMD_CORE
			o1[BUF_OFFSET_OF(SIMD_COEF_32, SHA_BUF_SIZ, j, 0)] = outbuf[j].i[0]
				= sha1_ctx.h0;
			o1[BUF_OFFSET_OF(SIMD_COEF_32, SHA_BUF_SIZ, j, 1)] = outbuf[j].i[1]
				= sha1_ctx.h1;
			o1[BUF_OFFSET_OF(SIMD_COEF_32, SHA_BUF_SIZ, j, 2)] = outbuf[j].i[2]
				= sha1_ctx.h2;
			o1[BUF_OFFSET_OF(SIMD_COEF_32, SHA_BUF_SIZ, j, 3)] = outbuf[j].i[3]
				= sha1_ctx.h3;
			o1[BUF_OFFSET_OF(SIMD_COEF_32, SHA_BUF_SIZ, j, 4)] = outbuf[j].i[4]
				= sha1_ctx.h4;
#else
			o1[BUF_OFFSET_OF(MMX_COEF, SHA_BUF_SIZ, j, 0)] = outbuf[j].i[0]
				= sha1_ctx.h0;
			o1[BUF_OFFSET_OF(MMX_COEF, SHA_BUF_SIZ, j, 1)] = outbuf[j].i[1]
				= sha1_ctx.h1;
			o1[BUF_OFFSET_OF(MMX_COEF, SHA_BUF_SIZ, j, 2)] = outbuf[j].i[2]
				= sha1_ctx.h2;
			o1[BUF_OFFSET_OF(MMX_COEF, SHA_BUF_SIZ, j, 3)] = outbuf[j].i[3]
				= sha1_ctx.h3;
			o1[BUF_OFFSET_OF(MMX_COEF, SHA_BUF_SIZ, j, 4)] = outbuf[j].i[4]
				= sha1_ctx.h4;
#endif
		}

		for (i = 1; i < 4096; i++)
		{
			SIMDSHA1body((unsigned int *) t_sse_hash1,
						 (unsigned int *) t_sse_hash1,
						 (unsigned int *) t_sse_crypt1,
						 SSEi_MIXED_IN | SSEi_RELOAD | SSEi_OUTPUT_AS_INP_FMT);
			SIMDSHA1body((unsigned int *) t_sse_hash1,
						 (unsigned int *) t_sse_hash1,
						 (unsigned int *) t_sse_crypt2,
						 SSEi_MIXED_IN | SSEi_RELOAD | SSEi_OUTPUT_AS_INP_FMT);

			for (j = 0; j < NBKEYS; j++)
			{
#ifdef SIMD_CORE
				uint32_t * p = SSE_HASH1_PTR_OF(j);
				for (k = 0; k < 5; k++) outbuf[j].i[k] ^= p[(k * SIMD_COEF_32)];
#else
				uint32_t * p = MMX_HASH1_PTR_OF(j);
				for (k = 0; k < 5; k++)
					outbuf[j].i[k] ^= p[(k << (MMX_COEF >> 1))];
#endif
			}
		}

		essid[slen - 1] = 2;
		for (j = 0; j < NBKEYS; ++j)
		{
			// This code does the HMAC(EVP_....) call. We already have essid
			// appended with BE((int)1) so we simply call a single SHA1_Update
			memcpy(&sha1_ctx, &ctx_ipad[j], sizeof(sha1_ctx));
			SHA1_Update(&sha1_ctx, essid, slen);
			SHA1_Final(&outbuf[j].c[20], &sha1_ctx);
			memcpy(&sha1_ctx, &ctx_opad[j], sizeof(sha1_ctx));
			SHA1_Update(&sha1_ctx, &outbuf[j].c[20], 20);
			SHA1_Final(&outbuf[j].c[20], &sha1_ctx);

// now convert this from flat into COEF buffers. Also, perform the
// 'first' ^= into the crypt buffer.  We are doing that in BE
// format so we will need to 'undo' that in the end.
// (only 3 dwords of the 2nd block outbuf are worked with).
#ifdef SIMD_CORE
			o1[BUF_OFFSET_OF(SIMD_COEF_32, SHA_BUF_SIZ, j, 0)] = outbuf[j].i[5]
				= sha1_ctx.h0;
			o1[BUF_OFFSET_OF(SIMD_COEF_32, SHA_BUF_SIZ, j, 1)] = outbuf[j].i[6]
				= sha1_ctx.h1;
			o1[BUF_OFFSET_OF(SIMD_COEF_32, SHA_BUF_SIZ, j, 2)] = outbuf[j].i[7]
				= sha1_ctx.h2;
			o1[BUF_OFFSET_OF(SIMD_COEF_32, SHA_BUF_SIZ, j, 3)] = sha1_ctx.h3;
			o1[BUF_OFFSET_OF(SIMD_COEF_32, SHA_BUF_SIZ, j, 4)] = sha1_ctx.h4;
#else
			o1[BUF_OFFSET_OF(MMX_COEF, SHA_BUF_SIZ, j, 0)] = outbuf[j].i[5]
				= sha1_ctx.h0;
			o1[BUF_OFFSET_OF(MMX_COEF, SHA_BUF_SIZ, j, 1)] = outbuf[j].i[6]
				= sha1_ctx.h1;
			o1[BUF_OFFSET_OF(MMX_COEF, SHA_BUF_SIZ, j, 2)] = outbuf[j].i[7]
				= sha1_ctx.h2;
			o1[BUF_OFFSET_OF(MMX_COEF, SHA_BUF_SIZ, j, 3)] = sha1_ctx.h3;
			o1[BUF_OFFSET_OF(MMX_COEF, SHA_BUF_SIZ, j, 4)] = sha1_ctx.h4;
#endif
		}
		for (i = 1; i < 4096; i++)
		{
			SIMDSHA1body((unsigned int *) t_sse_hash1,
						 (unsigned int *) t_sse_hash1,
						 (unsigned int *) t_sse_crypt1,
						 SSEi_MIXED_IN | SSEi_RELOAD | SSEi_OUTPUT_AS_INP_FMT);
			SIMDSHA1body((unsigned int *) t_sse_hash1,
						 (unsigned int *) t_sse_hash1,
						 (unsigned int *) t_sse_crypt2,
						 SSEi_MIXED_IN | SSEi_RELOAD | SSEi_OUTPUT_AS_INP_FMT);
			for (j = 0; j < NBKEYS; j++)
			{
#ifdef SIMD_CORE
				uint32_t * p = SSE_HASH1_PTR_OF(j);
				for (k = 5; k < 8; k++)
					outbuf[j].i[k] ^= p[((k - 5) * SIMD_COEF_32)];
#else
				uint32_t * p = MMX_HASH1_PTR_OF(j);
				for (k = 5; k < 8; k++)
					outbuf[j].i[k] ^= p[((k - 5) << (MMX_COEF >> 1))];
#endif
			}
		}

		for (j = 0; j < NBKEYS; ++j)
		{
			memcpy(&engine->thread_data[threadid]->pmk[j], //-V512
				   outbuf[j].c,
				   32);
			alter_endianity_to_BE((&engine->thread_data[threadid]->pmk[j]), 8);
		}
	}

	return;
}
#endif

void init_atoi()
{
	char * pos;

	memset(atoi64, 0x7F, sizeof(atoi64));
	for (pos = itoa64; pos != &itoa64[63]; pos++)
		atoi64[ARCH_INDEX(*pos)] = pos - itoa64;
}

#ifdef SIMD_CORE
//#define XDEBUG 1
//#define ODEBUG 1
int init_wpapsk(ac_crypto_engine_t * engine,
				const wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED],
				int nparallel,
				int threadid)
{
	int i = 0;
	int count = 0;

	// clear entire output table
	memset(engine->thread_data[threadid]->pmk,
		   0,
		   (sizeof(wpapsk_hash) * (nparallel)));

	{
		unsigned char * sse_hash1 = engine->thread_data[threadid]->hash1;

		int index;
		for (index = 0; index < nparallel; ++index)
		{
// set the length of all hash1 SSE buffer to 64+20 * 8 bits. The 64 is for the
// ipad/opad,
// the 20 is for the length of the SHA1 buffer that also gets into each crypt.
// Works for SSE2i and SSE2
#ifdef SIMD_CORE
			((unsigned int *)
				 sse_hash1)[15 * SIMD_COEF_32 + (index & (SIMD_COEF_32 - 1))
							+ (unsigned int) index / SIMD_COEF_32 * SHA_BUF_SIZ
								  * SIMD_COEF_32]
				= (84 << 3); // all encrypts are 64+20 bytes.
#else
			((unsigned int *)
				 sse_hash1)[15 * MMX_COEF + (index & (MMX_COEF - 1))
							+ (index >> (MMX_COEF >> 1)) * SHA_BUF_SIZ
								  * MMX_COEF]
				= (84 << 3); // all encrypts are 64+20 bytes.
#endif
			sse_hash1[GETPOS(20, index)] = 0x80;
		}
	}

	for (i = 0; i < nparallel; ++i)
	{
		char * tkey = (char *) key[i].v;

		if (*tkey != 0)
		{
//			set_key(tkey, i, inbuffer);
#ifdef XDEBUG
			printf(
				"key%d (inbuffer) = (%p) %s  VALID\n", i + 1, tkey, key[i].v);
#endif
			count = i + 1;
		}
	}

	wpapsk_sse(engine, threadid, count, key);

	return 0;
}
#endif