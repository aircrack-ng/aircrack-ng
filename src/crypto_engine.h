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


struct ac_crypto_engine
{
	char essid[64];
};

typedef struct ac_crypto_engine ac_crypto_engine_t;

/// global init. this could initialize threadid 1, but...
IMPORT int ac_crypto_engine_init(ac_crypto_engine_t *engine);
IMPORT void ac_crypto_engine_destroy(ac_crypto_engine_t *engine);

IMPORT void ac_crypto_engine_set_essid(ac_crypto_engine_t *engine, const char *essid);

/// per-thread-in-use init. separate to allow (possible) NUMA-local allocation.
IMPORT int ac_crypto_engine_thread_init(ac_crypto_engine_t *engine, int threadid);
IMPORT void ac_crypto_engine_thread_destroy(ac_crypto_engine_t *engine, int threadid);

/// acquire the width of simd we're compiled for.
IMPORT int ac_crypto_engine_simd_width();


IMPORT void ac_crypto_engine_calc_pmk(ac_crypto_engine_t *engine, char (*key)[MAX_THREADS], unsigned char *pmk[MAX_THREADS], int nparallel, int threadid);

IMPORT void ac_crypto_engine_calc_ptk(ac_crypto_engine_t *engine, unsigned char *pmk[MAX_THREADS], unsigned char (pke)[100], unsigned char (ptk)[8][80], int vectorIdx, int threadid);
IMPORT void ac_crypto_engine_calc_mic(ac_crypto_engine_t *engine, uint8_t eapol[256], uint32_t eapol_size, unsigned char (ptk)[8][80], uint8_t mic[8][20], uint8_t keyver, int vectorIdx);

#ifdef __cplusplus
}
#endif

#endif //AIRCRACK_NG_CRYPTO_ENGINE_H
