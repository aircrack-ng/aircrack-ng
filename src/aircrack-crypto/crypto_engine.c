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
#include "wpapsk.h"
#ifdef USE_GCRYPT
#include "gcrypt-openssl-wrapper.h"
#include "sha1-git.h"
#else
#include <openssl/hmac.h>
#include <openssl/sha.h>
// We don't use EVP. Bite me
#include <openssl/rc4.h>
#include <openssl/aes.h>
#endif

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

	engine->essid =
		mem_calloc_align(ESSID_LENGTH + 1, sizeof(char), MEM_ALIGN_SIMD);

	return 0;
}

EXPORT void ac_crypto_engine_destroy(ac_crypto_engine_t *engine)
{
	assert(engine != NULL && "Engine is NULL");
#ifdef XDEBUG
	fprintf(stderr, "ac_crypto_engine_destroy(%p)\n", engine);
#endif

	MEM_FREE(engine->essid);
	engine->essid = NULL;
}

EXPORT void ac_crypto_engine_set_essid(ac_crypto_engine_t *engine,
									   const uint8_t *essid)
{
	assert(engine != NULL && "Engine is NULL");
#ifdef XDEBUG
	fprintf(stderr, "ac_crypto_engine_set_essid(%p, %s)\n", engine, essid);
#endif
	memccpy(engine->essid, essid, 0, ESSID_LENGTH);
	engine->essid_length = strlen((char*) essid);
}

EXPORT int ac_crypto_engine_thread_init(ac_crypto_engine_t *engine,
										int threadid)
{
	assert(engine != NULL && "Engine is NULL");
#ifdef XDEBUG
	fprintf(stderr, "ac_crypto_engine_thread_init(%p, %d)\n", engine, threadid);
#endif

	// allocate pairwise master key buffer, for ourselves (a thread.)
	engine->pmk[threadid] = mem_calloc_align(
		MAX_KEYS_PER_CRYPT, sizeof(wpapsk_hash) + 4, MEM_ALIGN_SIMD);

	engine->xsse_hash1[threadid] =
		mem_calloc_align(MAX_KEYS_PER_CRYPT, (84 << 3), MEM_ALIGN_SIMD);

	engine->xsse_crypt1[threadid] =
		mem_calloc_align(MAX_KEYS_PER_CRYPT, 20, MEM_ALIGN_SIMD);

	engine->xsse_crypt2[threadid] =
		mem_calloc_align(MAX_KEYS_PER_CRYPT, 20, MEM_ALIGN_SIMD);

	engine->ptk[threadid] =
		mem_calloc_align(MAX_KEYS_PER_CRYPT, 80 + 64, MEM_ALIGN_SIMD);

	engine->pke[threadid] =
		mem_calloc_align(MAX_KEYS_PER_CRYPT, 100 + 64, MEM_ALIGN_SIMD);

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

	if (engine->ptk[threadid] != NULL)
	{
		MEM_FREE(engine->ptk[threadid]);
		engine->ptk[threadid] = NULL;
	}

	if (engine->pke[threadid] != NULL)
	{
		MEM_FREE(engine->pke[threadid]);
		engine->pke[threadid] = NULL;
	}

	if (engine->pmk[threadid] != NULL)
	{
		MEM_FREE(engine->pmk[threadid]);
		engine->pmk[threadid] = NULL;
	}
}

EXPORT void ac_crypto_engine_calc_pke(ac_crypto_engine_t *engine,
									  const uint8_t bssid[6],
									  const uint8_t stmac[6],
									  const uint8_t anonce[32],
									  const uint8_t snonce[32],
									  int threadid)
{
	uint8_t *pke = engine->pke[threadid];

	assert(pke != NULL && "Forget to initialize thread?");

	/* pre-compute the key expansion buffer */
	memcpy(pke, "Pairwise key expansion", 23);
	if (memcmp(stmac, bssid, 6) < 0)
	{
		memcpy(pke + 23, stmac, 6);
		memcpy(pke + 29, bssid, 6);
	}
	else
	{
		memcpy(pke + 23, bssid, 6);
		memcpy(pke + 29, stmac, 6);
	}
	if (memcmp(snonce, anonce, 32) < 0)
	{
		memcpy(pke + 35, snonce, 32);
		memcpy(pke + 67, anonce, 32);
	}
	else
	{
		memcpy(pke + 35, anonce, 32);
		memcpy(pke + 67, snonce, 32);
	}
}

/* derive the PMK from the passphrase and the essid */
EXPORT void ac_crypto_engine_calc_one_pmk(const uint8_t *key,
										  const uint8_t *essid_pre,
										  uint32_t essid_pre_len,
										  uint8_t pmk[40])
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
	strncpy((char *) buffer, (char*) key, sizeof(buffer) - 1);

	for (i = 0; i < 64; i++) buffer[i] ^= 0x36;

	SHA1_Init(&ctx_ipad);
	SHA1_Update(&ctx_ipad, buffer, 64);

	for (i = 0; i < 64; i++) buffer[i] ^= 0x6A;

	SHA1_Init(&ctx_opad);
	SHA1_Update(&ctx_opad, buffer, 64);

	/* iterate HMAC-SHA1 over itself 8192 times */

	essid[slen - 1] = '\1';
	HMAC(EVP_sha1(),
		 key,
		 (int) strlen((char*) key),
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
		 (int) strlen((char*) key),
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

EXPORT void
ac_crypto_engine_calc_pmk(ac_crypto_engine_t *engine,
						  const wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED],
						  const int nparallel,
						  const int threadid)
{
// PMK calculation
#ifdef SIMD_CORE
	if (nparallel >= 4)
	{
		init_wpapsk(engine, key, nparallel, threadid);
	}
	else
#endif
		for (int j = 0; j < nparallel; ++j)
		{
#ifdef XDEBUG
			printf("%lu: Trying: %s\n", pthread_self(), (char *) key[j].v);
#endif
			ac_crypto_engine_calc_one_pmk(
				key[j].v,
				(uint8_t*) engine->essid,
				engine->essid_length,
				(unsigned char *) (engine->pmk[threadid]
								   + (sizeof(wpapsk_hash) * j)));
		}
}

EXPORT void ac_crypto_engine_calc_ptk(ac_crypto_engine_t *engine,
									  int vectorIdx,
									  int threadid)
{
	uint8_t *ptk = engine->ptk[threadid];

	for (int i = 0; i < 4; i++)
	{
		*(engine->pke[threadid] + 99) = (unsigned char) i;

		HMAC(EVP_sha1(),
			 engine->pmk[threadid] + (sizeof(wpapsk_hash) * vectorIdx),
			 32,
			 engine->pke[threadid],
			 100,
			 &ptk[vectorIdx] + i * 20,
			 NULL);
	}
}

EXPORT void ac_crypto_engine_calc_mic(ac_crypto_engine_t *engine,
									  const uint8_t eapol[256],
									  const uint32_t eapol_size,
									  uint8_t mic[MAX_KEYS_PER_CRYPT_SUPPORTED][20],
									  const uint8_t keyver,
									  const int vectorIdx,
									  const int threadid)
{
	uint8_t *ptk = engine->ptk[threadid];

	if (keyver == 1)
		HMAC(EVP_md5(),
			 &ptk[vectorIdx],
			 16,
			 eapol,
			 eapol_size,
			 mic[vectorIdx],
			 NULL);
	else
		HMAC(EVP_sha1(),
			 &ptk[vectorIdx],
			 16,
			 eapol,
			 eapol_size,
			 mic[vectorIdx],
			 NULL);
}

EXPORT int
ac_crypto_engine_wpa_crack(ac_crypto_engine_t *engine,
						   const wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED],
						   const uint8_t eapol[256],
						   const uint32_t eapol_size,
						   uint8_t mic[MAX_KEYS_PER_CRYPT_SUPPORTED][20],
						   const uint8_t keyver,
						   const uint8_t cmpmic[20],
						   const int nparallel,
						   const int threadid)
{
	ac_crypto_engine_calc_pmk(engine, key, nparallel, threadid);

	for (int j = 0; j < nparallel; ++j)
	{
		/* compute the pairwise transient key and the frame MIC */

		ac_crypto_engine_calc_ptk(engine, j, threadid);

		ac_crypto_engine_calc_mic(
			engine, eapol, eapol_size, mic, keyver, j, threadid);

		/* did we successfully crack it? */
		if (memcmp(mic[j], cmpmic, 16) == 0)
		{
			return j;
		}
	}

	return -1;
}