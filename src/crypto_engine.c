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
	fprintf(stderr, "ac_crypto_engine_init(%p)\n", engine);
	init_atoi();
	return 0;
}

EXPORT void ac_crypto_engine_destroy(ac_crypto_engine_t *engine)
{
	assert(engine != NULL && "Engine is NULL");
	fprintf(stderr, "ac_crypto_engine_destroy(%p)\n", engine);
}

EXPORT void ac_crypto_engine_set_essid(ac_crypto_engine_t *engine, const char *essid)
{
	assert(engine != NULL && "Engine is NULL");
	fprintf(stderr, "ac_crypto_engine_set_essid(%p, %s)\n", engine, essid);
	memccpy(engine->essid, essid, 0, sizeof(engine->essid));
}

EXPORT int ac_crypto_engine_thread_init(ac_crypto_engine_t *engine, int threadid)
{
	assert(engine != NULL && "Engine is NULL");
	fprintf(stderr, "ac_crypto_engine_thread_init(%p, %d)\n", engine, threadid);
	init_ssecore(threadid);
	//init_atoi();
	return 0;
}

EXPORT void ac_crypto_engine_thread_destroy(ac_crypto_engine_t *engine, int threadid)
{
	assert(engine != NULL && "Engine is NULL");
	fprintf(stderr, "ac_crypto_engine_thread_destroy(%p, %d)\n", engine, threadid);
	free_ssecore(threadid);
}

EXPORT void ac_crypto_engine_calc_pmk(ac_crypto_engine_t *engine, char (*key)[MAX_THREADS], unsigned char *pmk[MAX_THREADS], int nparallel, int threadid)
{
	// PMK calculation
	if (nparallel >= 4)
	{
		init_wpapsk(key, engine->essid, nparallel, threadid);
	}
	else
		for (int j = 0; j < nparallel; ++j)
			calc_pmk(key[j],
					 engine->essid,
					 (unsigned char *) (pmk[threadid]
						 + (sizeof(wpapsk_hash) * j)));
}

EXPORT void ac_crypto_engine_calc_ptk(ac_crypto_engine_t *engine, unsigned char *pmk[MAX_THREADS], unsigned char (pke)[100], unsigned char (ptk)[8][80], int vectorIdx, int threadid)
{
	for (int i = 0; i < 4; i++)
	{
		pke[99] = (unsigned char) i;

		HMAC(EVP_sha1(),
			 pmk[threadid] + (sizeof(wpapsk_hash) * vectorIdx),
			 32,
			 pke,
			 100,
			 ptk[vectorIdx] + i * 20,
			 NULL);
	}
}

EXPORT void ac_crypto_engine_calc_mic(ac_crypto_engine_t *engine, uint8_t eapol[256], uint32_t eapol_size, unsigned char (ptk)[8][80], uint8_t mic[8][20], uint8_t keyver, int vectorIdx)
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