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

#ifndef AIRCRACK_NG_CRYPTO_ENGINE_H
#define AIRCRACK_NG_CRYPTO_ENGINE_H

#include <string.h>
#include <stdint.h>

#define MAX_THREADS 256

#if defined(_MSC_VER)
//  Microsoft
#define EXPORT __declspec(dllexport)
#define IMPORT __declspec(dllimport)
#elif defined(__GNUC__) || defined(__llvm__) || defined(__clang__)             \
	|| defined(__INTEL_COMPILER)
#define EXPORT __attribute__((visibility("default")))
#define IMPORT
#else
//  do nothing and hope for the best?
#define EXPORT
#define IMPORT
#pragma warning Unknown dynamic link import / export semantics.
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define PLAINTEXT_LENGTH 63 /* We can do 64 but spec. says 63 */

#define MIN_KEYS_PER_CRYPT 1
#ifdef JOHN_AVX2
#define MAX_KEYS_PER_CRYPT 8
#else
#define MAX_KEYS_PER_CRYPT 4
#endif

typedef struct
{
	uint32_t length;
	uint8_t v[PLAINTEXT_LENGTH + 1];
} wpapsk_password;

typedef struct
{
	uint32_t v[8];
} wpapsk_hash;

//struct ac_crypto_engine_thread_priv
//{
//  unsigned char *pmk[MAX_THREADS];
//};

struct ac_crypto_engine
{
	//	char essid[64];
	char *essid;

	//	struct ac_crypto_engine_thread_priv priv[MAX_THREADS];

	unsigned char *pmk[MAX_THREADS];

	wpapsk_password *wpapass[MAX_THREADS];

	unsigned char *xsse_hash1[MAX_THREADS];
	unsigned char *xsse_crypt1[MAX_THREADS];
	unsigned char *xsse_crypt2[MAX_THREADS];
};

typedef struct ac_crypto_engine ac_crypto_engine_t;

/// global init. this could initialize threadid 1, but...
IMPORT int ac_crypto_engine_init(ac_crypto_engine_t *engine);
IMPORT void ac_crypto_engine_destroy(ac_crypto_engine_t *engine);

IMPORT void ac_crypto_engine_set_essid(ac_crypto_engine_t *engine,
									   const char *essid);

static inline unsigned char *
ac_crypto_engine_get_pmk(ac_crypto_engine_t *engine, int threadid)
{
	return engine->pmk[threadid];
}

/// per-thread-in-use init. separate to allow (possible) NUMA-local allocation.
IMPORT int ac_crypto_engine_thread_init(ac_crypto_engine_t *engine,
										int threadid);
IMPORT void ac_crypto_engine_thread_destroy(ac_crypto_engine_t *engine,
											int threadid);

/// acquire the width of simd we're compiled for.
IMPORT int ac_crypto_engine_simd_width();

IMPORT void ac_crypto_engine_calc_pmk(ac_crypto_engine_t *engine,
									  char (*key)[MAX_THREADS],
									  int nparallel,
									  int threadid);

IMPORT void ac_crypto_engine_calc_ptk(ac_crypto_engine_t *engine,
									  unsigned char(pke)[100],
									  unsigned char(ptk)[8][80],
									  int vectorIdx,
									  int threadid);
IMPORT void ac_crypto_engine_calc_mic(ac_crypto_engine_t *engine,
									  uint8_t eapol[256],
									  uint32_t eapol_size,
									  unsigned char(ptk)[8][80],
									  uint8_t mic[8][20],
									  uint8_t keyver,
									  int vectorIdx);

IMPORT int ac_crypto_engine_wpa_crack(ac_crypto_engine_t *engine,
									  char (*key)[MAX_THREADS],
									  unsigned char(pke)[100],
									  uint8_t eapol[256],
									  uint32_t eapol_size,
									  unsigned char(ptk)[8][80],
									  uint8_t mic[8][20],
									  uint8_t keyver,
									  const uint8_t cmpmic[20],
									  int nparallel,
									  int threadid);

// Quick Utilities.

/// Calculate one pairwise master key, from the \a essid and \a key.
IMPORT void
ac_crypto_engine_calc_one_pmk(char *key, char *essid, unsigned char pmk[40]);

#ifdef __cplusplus
}
#endif

#endif //AIRCRACK_NG_CRYPTO_ENGINE_H
