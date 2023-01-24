/*
 * Copyright (C) 2018-2022 Joseph Benden <joe@benden.us>
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301, USA.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <err.h>
#include <limits.h>
#define _GNU_SOURCE
#include <string.h>
#include <stdint.h>

#include "aircrack-ng/crypto/crypto.h"
#include "aircrack-ng/ce-wpa/simd-intrinsics.h"
#include "aircrack-ng/ce-wpa/wpapsk.h"
#include "aircrack-ng/cpu/trampoline.h"
#include "aircrack-ng/ce-wpa/crypto_engine.h"

// #define XDEBUG

EXPORT int ac_crypto_engine_supported_features(void)
{
#if defined(JOHN_AVX512F)
	return SIMD_SUPPORTS_AVX512F;
#elif defined(JOHN_AVX2)
	return SIMD_SUPPORTS_AVX2;
#elif defined(JOHN_AVX)
	return SIMD_SUPPORTS_AVX;
#elif defined(JOHN_SSE2)
	return SIMD_SUPPORTS_SSE2;
#elif defined(JOHN_NEON)
	return SIMD_SUPPORTS_NEON;
#elif defined(JOHN_ASIMD)
	return SIMD_SUPPORTS_ASIMD;
#elif defined(JOHN_POWER8)
	return SIMD_SUPPORTS_POWER8;
#elif defined(JOHN_ALTIVEC)
	return SIMD_SUPPORTS_ALTIVEC;
#else
	return SIMD_SUPPORTS_NONE;
#endif
}

EXPORT int ac_crypto_engine_simd_width(void)
{
#ifdef SIMD_COEF_32
	return SIMD_COEF_32;
#else
	return 1;
#endif
}

EXPORT int ac_crypto_engine_init(ac_crypto_engine_t * engine)
{
	assert(engine != NULL);
#ifdef XDEBUG
	fprintf(stderr, "ac_crypto_engine_init(%p)\n", engine);
#endif

	init_atoi();

	engine->essid = mem_calloc_align(1, ESSID_LENGTH + 1, MEM_ALIGN_SIMD);

	engine->essid_length = 0;

	for (int i = 0; i < MAX_THREADS; ++i) engine->thread_data[i] = NULL;

	return 0;
}

EXPORT void ac_crypto_engine_destroy(ac_crypto_engine_t * engine)
{
	assert(engine != NULL);
#ifdef XDEBUG
	fprintf(stderr, "ac_crypto_engine_destroy(%p)\n", engine);
#endif

	MEM_FREE(engine->essid);
}

EXPORT void ac_crypto_engine_set_essid(ac_crypto_engine_t * engine,
									   const uint8_t * essid)
{
	assert(engine != NULL);
#ifdef XDEBUG
	fprintf(stderr, "ac_crypto_engine_set_essid(%p, %s)\n", engine, essid);
#endif
	memccpy(engine->essid, essid, 0, ESSID_LENGTH);
	engine->essid_length = (uint32_t) strlen((char *) essid);
}

EXPORT int ac_crypto_engine_thread_init(ac_crypto_engine_t * engine,
										int threadid)
{
	assert(engine != NULL);
#ifdef XDEBUG
	fprintf(stderr, "ac_crypto_engine_thread_init(%p, %d)\n", engine, threadid);
#endif

	// allocate per-thread data.
	engine->thread_data[threadid] = mem_calloc_align(
		1, sizeof(struct ac_crypto_engine_perthread), MEM_ALIGN_SIMD);

	return 0;
}

EXPORT void ac_crypto_engine_thread_destroy(ac_crypto_engine_t * engine,
											int threadid)
{
	assert(engine != NULL);
#ifdef XDEBUG
	fprintf(
		stderr, "ac_crypto_engine_thread_destroy(%p, %d)\n", engine, threadid);
#endif

	if (engine->thread_data[threadid] != NULL)
	{
		MEM_FREE(engine->thread_data[threadid]);
	}
}

EXPORT uint8_t *
ac_crypto_engine_get_pmk(ac_crypto_engine_t * engine, int threadid, int index)
{
	return (uint8_t *) engine->thread_data[threadid]->pmk
		   + (sizeof(wpapsk_hash) * index);
}

EXPORT uint8_t *
ac_crypto_engine_get_ptk(ac_crypto_engine_t * engine, int threadid, int index)
{
	return (uint8_t *) engine->thread_data[threadid]->ptk + (20 * index);
}

EXPORT void ac_crypto_engine_calc_pke(ac_crypto_engine_t * engine,
									  const uint8_t bssid[6],
									  const uint8_t stmac[6],
									  const uint8_t anonce[32],
									  const uint8_t snonce[32],
									  int threadid)
{
	uint8_t * pke = engine->thread_data[threadid]->pke;

	assert(pke != NULL); //-V547

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
EXPORT void ac_crypto_engine_calc_one_pmk(const uint8_t * key,
										  const uint8_t * essid_pre,
										  uint32_t essid_pre_len,
										  uint8_t pmk[static PMK_LEN])
{
	if (KDF_PBKDF2_SHA1(key, essid_pre, essid_pre_len, 4096, pmk, PMK_LEN) != 0)
		errx(1, "Failed to compute PBKDF2 HMAC-SHA1");
}

EXPORT void ac_crypto_engine_calc_pmk(
	ac_crypto_engine_t * engine,
	const wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED],
	const int nparallel,
	const int threadid)
{
	wpapsk_hash * pmk = engine->thread_data[threadid]->pmk;

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
			ac_crypto_engine_calc_one_pmk(key[j].v,
										  (uint8_t *) engine->essid,
										  engine->essid_length,
										  (uint8_t *) (&pmk[j]));
		}
}

EXPORT void ac_crypto_engine_calc_ptk(ac_crypto_engine_t * engine,
									  const uint8_t keyver,
									  int vectorIdx,
									  int threadid)
{
	uint8_t data[64 + 12];

	uint8_t * ptk = engine->thread_data[threadid]->ptk;
	wpapsk_hash * pmk = engine->thread_data[threadid]->pmk;
	uint8_t * pke = &engine->thread_data[threadid]->pke[23];

	memset(data,                0,              sizeof(data));
	memcpy(data,                pke,            ETH_ALEN);
	memcpy(data + ETH_ALEN,     pke + ETH_ALEN, ETH_ALEN);
	memcpy(data + 2 * ETH_ALEN, pke + 35 - 23,  64); //-V512

	if (keyver < 3)
	{
		SHA1_PRF((const uint8_t *) (&pmk[vectorIdx]),
				 32,
				 (const uint8_t *) "Pairwise key expansion",
				 data,
				 76,
				 &ptk[vectorIdx],
				 4 * DIGEST_SHA1_MAC_LEN);
	}
	else
	{
		Digest_SHA256_PRF_Bits((const uint8_t *) (&pmk[vectorIdx]),
							   32,
							   (const uint8_t *) "Pairwise key expansion",
							   data,
							   76,
							   ptk,
							   48 * CHAR_BIT);
	}
}

EXPORT void ac_crypto_engine_calc_mic(ac_crypto_engine_t * engine,
									  const uint8_t eapol[256],
									  const uint32_t eapol_size,
									  uint8_t mic[MAX_KEYS_PER_CRYPT_SUPPORTED]
												 [20],
									  const uint8_t keyver,
									  const int vectorIdx,
									  const int threadid)
{
	uint8_t * ptk = engine->thread_data[threadid]->ptk;

	if (keyver == 1)
		MAC_HMAC_MD5(16, &ptk[vectorIdx], eapol_size, eapol, mic[vectorIdx]);
	else if (keyver == 2)
		MAC_HMAC_SHA1(16, &ptk[vectorIdx], eapol_size, eapol, mic[vectorIdx]);
	else if (keyver == 3)
	{
		const uint8_t * addr[4];
		size_t len[4];

		addr[0] = eapol;
		len[0] = eapol_size;
		MAC_OMAC1_AES_Vector(
			16, ptk, 1, addr, len, (uint8_t *) &mic[vectorIdx]);
	}
	else
	{
		fprintf(stderr, "Unsupported key version %d encountered.\n", keyver);
		if (keyver == 0) fprintf(stderr, "May be WPA3 - not yet supported.\n");
		abort();
	}
}

EXPORT int ac_crypto_engine_wpa_crack(
	ac_crypto_engine_t * engine,
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

		ac_crypto_engine_calc_ptk(engine, keyver, j, threadid);

		ac_crypto_engine_calc_mic(
			engine, eapol, eapol_size, mic, keyver, j, threadid);

		/* did we successfully crack it? */
		if (memcmp(mic[j], cmpmic, 16) == 0) //-V512
		{
			return j;
		}
	}

	return -1;
}

EXPORT void ac_crypto_engine_set_pmkid_salt(ac_crypto_engine_t * engine,
											const uint8_t bssid[6],
											const uint8_t stmac[6],
											int threadid)
{
	uint8_t * pke = engine->thread_data[threadid]->pke;

	assert(pke != NULL); //-V547

	/* pre-compute the PMKID salt buffer */
	memcpy(pke, "PMK Name", 8);
	memcpy(pke + 8, bssid, 6);
	memcpy(pke + 14, stmac, 6);
}

EXPORT int ac_crypto_engine_wpa_pmkid_crack(
	ac_crypto_engine_t * engine,
	const wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED],
	const uint8_t pmkid[32],
	const int nparallel,
	const int threadid)
{
	ac_crypto_engine_calc_pmk(engine, key, nparallel, threadid);

	uint8_t * pke = engine->thread_data[threadid]->pke;
	wpapsk_hash * pmk = engine->thread_data[threadid]->pmk;
	uint8_t l_pmkid[DIGEST_SHA1_MAC_LEN];

	for (int j = 0; j < nparallel; ++j)
	{
		MAC_HMAC_SHA1(32, (const uint8_t *) &pmk[j], 20, pke, l_pmkid);

		/* did we successfully crack it? */
		if (memcmp(l_pmkid, pmkid, 16) == 0) //-V512
		{
			return j;
		}
	}

	return -1;
}
