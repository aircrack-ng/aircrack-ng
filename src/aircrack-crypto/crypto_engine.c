/*
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * is provided AS IS, WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, and
 * NON-INFRINGEMENT.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */

#include <string.h>
#include <stdint.h>
#ifdef SIMD_CORE
#include "simd-intrinsics.h"
#else
#include "sse-intrinsics.h"
#endif
#include "crypto.h"
#include "wpapsk.h"

#include "crypto_engine.h"

// #define XDEBUG

EXPORT int ac_crypto_engine_simd_width()
{
#ifdef SIMD_COEF_32
	return SIMD_COEF_32;
#else
	return 1;
#endif
}

EXPORT int ac_crypto_engine_init(ac_crypto_engine_t *engine)
{
	assert(engine != NULL && "Engine is NULL");
#ifdef XDEBUG
	fprintf(stderr, "ac_crypto_engine_init(%p)\n", engine);
#endif

	init_atoi();

	engine->essid = mem_calloc_align(64, sizeof(char), MEM_ALIGN_SIMD);
	memset(engine->pmk, 0, sizeof(engine->pmk));

	return 0;
}

EXPORT void ac_crypto_engine_destroy(ac_crypto_engine_t *engine)
{
	assert(engine != NULL && "Engine is NULL");
#ifdef XDEBUG
	fprintf(stderr, "ac_crypto_engine_destroy(%p)\n", engine);
#endif

	MEM_FREE(engine->essid);
}

EXPORT void ac_crypto_engine_set_essid(ac_crypto_engine_t *engine,
									   const char *essid)
{
	assert(engine != NULL && "Engine is NULL");
#ifdef XDEBUG
	fprintf(stderr, "ac_crypto_engine_set_essid(%p, %s)\n", engine, essid);
#endif
	memccpy(engine->essid, essid, 0, sizeof(engine->essid));
	engine->essid_length = strlen(essid);
}

EXPORT int ac_crypto_engine_thread_init(ac_crypto_engine_t *engine,
										int threadid)
{
	assert(engine != NULL && "Engine is NULL");
#ifdef XDEBUG
	fprintf(stderr, "ac_crypto_engine_thread_init(%p, %d)\n", engine, threadid);
#endif

	engine->xsse_hash1[threadid] =
		mem_calloc_align(MAX_KEYS_PER_CRYPT, 84 << 3, MEM_ALIGN_SIMD);

	engine->xsse_crypt1[threadid] =
		mem_calloc_align(MAX_KEYS_PER_CRYPT, 20, MEM_ALIGN_SIMD);

	engine->xsse_crypt2[threadid] =
		mem_calloc_align(MAX_KEYS_PER_CRYPT, 20, MEM_ALIGN_SIMD);

	engine->wpapass[threadid] =
		mem_calloc_align(MAX_KEYS_PER_CRYPT, sizeof(wpapsk_password), MEM_ALIGN_SIMD);

	// allocate pairwise master key buffer, for ourselves (a thread.)
	engine->pmk[threadid] = mem_calloc_align(
		MAX_KEYS_PER_CRYPT, sizeof(wpapsk_hash), MEM_ALIGN_SIMD);

	return 0;
}

EXPORT void ac_crypto_engine_thread_destroy(ac_crypto_engine_t *engine,
											int threadid)
{
	assert(engine != NULL && "Engine is NULL");
#ifdef XDEBUG
	fprintf(
		stderr, "ac_crypto_engine_thread_destroy(%p, %d)\n", engine, threadid);
#endif

	if (engine->xsse_hash1[threadid] != NULL)
	{
		MEM_FREE(engine->xsse_hash1[threadid]);
		engine->xsse_hash1[threadid] = NULL;
	}

	if (engine->xsse_crypt1[threadid] != NULL)
	{
		MEM_FREE(engine->xsse_crypt1[threadid]);
		engine->xsse_crypt1[threadid] = NULL;
	}

	if (engine->xsse_crypt2[threadid] != NULL)
	{
		MEM_FREE(engine->xsse_crypt2[threadid]);
		engine->xsse_crypt2[threadid] = NULL;
	}

	if (engine->wpapass[threadid] != NULL)
	{
		MEM_FREE(engine->wpapass[threadid]);
		engine->wpapass[threadid] = NULL;
	}

	if (engine->pmk[threadid] != NULL)
	{
		MEM_FREE(engine->pmk[threadid]);
		engine->pmk[threadid] = NULL;
	}
}

/* derive the PMK from the passphrase and the essid */
EXPORT void
ac_crypto_engine_calc_one_pmk(char *key, char *essid_pre, uint32_t essid_pre_len, unsigned char pmk[40])
{
	int i, j, slen;
	unsigned char buffer[65];
	char essid[33 + 4];
	SHA_CTX ctx_ipad;
	SHA_CTX ctx_opad;
	SHA_CTX sha1_ctx;

	if (essid_pre == NULL || essid_pre[0] == 0 || essid_pre_len > 32)
	{
		return;
	}

	memset(essid, 0, sizeof(essid));
	memcpy(essid, essid_pre, essid_pre_len);
	slen = (int) essid_pre_len + 4;

	/* setup the inner and outer contexts */

	memset(buffer, 0, sizeof(buffer));
	strncpy((char *) buffer, key, sizeof(buffer) - 1);

	for (i = 0; i < 64; i++) buffer[i] ^= 0x36;

	SHA1_Init(&ctx_ipad);
	SHA1_Update(&ctx_ipad, buffer, 64);

	for (i = 0; i < 64; i++) buffer[i] ^= 0x6A;

	SHA1_Init(&ctx_opad);
	SHA1_Update(&ctx_opad, buffer, 64);

	/* iterate HMAC-SHA1 over itself 8192 times */

	essid[slen - 1] = '\1';
	HMAC(EVP_sha1(),
		 (unsigned char *) key,
		 (int) strlen(key),
		 (unsigned char *) essid,
		 (size_t) slen,
		 pmk,
		 NULL);
	memcpy(buffer, pmk, 20);

	for (i = 1; i < 4096; i++)
	{
		memcpy(&sha1_ctx, &ctx_ipad, sizeof(sha1_ctx));
		SHA1_Update(&sha1_ctx, buffer, 20);
		SHA1_Final(buffer, &sha1_ctx);

		memcpy(&sha1_ctx, &ctx_opad, sizeof(sha1_ctx));
		SHA1_Update(&sha1_ctx, buffer, 20);
		SHA1_Final(buffer, &sha1_ctx);

		for (j = 0; j < 20; j++) pmk[j] ^= buffer[j];
	}

	essid[slen - 1] = '\2';
	HMAC(EVP_sha1(),
		 (unsigned char *) key,
		 (int) strlen(key),
		 (unsigned char *) essid,
		 (size_t) slen,
		 pmk + 20,
		 NULL);
	memcpy(buffer, pmk + 20, 20);

	for (i = 1; i < 4096; i++)
	{
		memcpy(&sha1_ctx, &ctx_ipad, sizeof(sha1_ctx));
		SHA1_Update(&sha1_ctx, buffer, 20);
		SHA1_Final(buffer, &sha1_ctx);

		memcpy(&sha1_ctx, &ctx_opad, sizeof(sha1_ctx));
		SHA1_Update(&sha1_ctx, buffer, 20);
		SHA1_Final(buffer, &sha1_ctx);

		for (j = 0; j < 20; j++) pmk[j + 20] ^= buffer[j];
	}
}

EXPORT void ac_crypto_engine_calc_pmk(ac_crypto_engine_t *engine,
									  char (*key)[MAX_THREADS],
									  int nparallel,
									  int threadid)
{
	// PMK calculation
	if (nparallel >= 4)
	{
		init_wpapsk(
			engine, key, nparallel, threadid);
	}
	else
		for (int j = 0; j < nparallel; ++j)
			ac_crypto_engine_calc_one_pmk(
				key[j],
				engine->essid,
				engine->essid_length,
				(unsigned char *) (engine->pmk[threadid]
								   + (sizeof(wpapsk_hash) * j)));
}

EXPORT void ac_crypto_engine_calc_ptk(ac_crypto_engine_t *engine,
									  unsigned char(pke)[100],
									  unsigned char(ptk)[8][80],
									  int vectorIdx,
									  int threadid)
{
	for (int i = 0; i < 4; i++)
	{
		pke[99] = (unsigned char) i;

		HMAC(EVP_sha1(),
			 engine->pmk[threadid] + (sizeof(wpapsk_hash) * vectorIdx),
			 32,
			 pke,
			 100,
			 ptk[vectorIdx] + i * 20,
			 NULL);
	}
}

EXPORT void ac_crypto_engine_calc_mic(ac_crypto_engine_t *engine,
									  uint8_t eapol[256],
									  uint32_t eapol_size,
									  unsigned char(ptk)[8][80],
									  uint8_t mic[8][20],
									  uint8_t keyver,
									  int vectorIdx)
{

	if (keyver == 1)
		HMAC(EVP_md5(),
			 ptk[vectorIdx],
			 16,
			 eapol,
			 eapol_size,
			 mic[vectorIdx],
			 NULL);
	else
		HMAC(EVP_sha1(),
			 ptk[vectorIdx],
			 16,
			 eapol,
			 eapol_size,
			 mic[vectorIdx],
			 NULL);
}

EXPORT int ac_crypto_engine_wpa_crack(ac_crypto_engine_t *engine,
									  char (*key)[MAX_THREADS],
									  unsigned char(pke)[100],
									  uint8_t eapol[256],
									  uint32_t eapol_size,
									  unsigned char(ptk)[8][80],
									  uint8_t mic[8][20],
									  uint8_t keyver,
									  const uint8_t cmpmic[20],
									  int nparallel,
									  int threadid)
{
	ac_crypto_engine_calc_pmk(engine, key, nparallel, threadid);

	for (int j = 0; j < nparallel; ++j)
	{
		/* compute the pairwise transient key and the frame MIC */

		ac_crypto_engine_calc_ptk(engine, pke, ptk, j, threadid);

		ac_crypto_engine_calc_mic(
			engine, eapol, eapol_size, ptk, mic, keyver, j);

		/* did we successfully crack it? */
		if (memcmp(mic[j], cmpmic, 16) == 0)
		{
			return j;
		}
	}

	return -1;
}