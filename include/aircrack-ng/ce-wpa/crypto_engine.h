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

#ifndef AIRCRACK_NG_CRYPTO_ENGINE_H
#define AIRCRACK_NG_CRYPTO_ENGINE_H

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include <aircrack-ng/defs.h>

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

#define ESSID_LENGTH 32 /* The spec. says 32 maximum. */
#define PLAINTEXT_LENGTH 63 /* We can do 64 but spec. says 63 */
#define PMK_LEN 32
#define PMK_LEN_MAX 64

#define MIN_KEYS_PER_CRYPT 1
#if defined(JOHN_AVX512F)
#define MAX_KEYS_PER_CRYPT 16
#elif defined(JOHN_AVX2)
#define MAX_KEYS_PER_CRYPT 8
#else
#define MAX_KEYS_PER_CRYPT 4
#endif

#if defined(AVX512F_FOUND)
#if defined(__INTEL_COMPILER)
#define MAX_KEYS_PER_CRYPT_SUPPORTED 32
#else
#define MAX_KEYS_PER_CRYPT_SUPPORTED 16
#endif
#else
#if defined(__INTEL_COMPILER)
#define MAX_KEYS_PER_CRYPT_SUPPORTED 16
#else
#define MAX_KEYS_PER_CRYPT_SUPPORTED 8
#endif
#endif

typedef struct
{
	uint8_t v[PLAINTEXT_LENGTH + 1];
	uint32_t length;
} wpapsk_password;

typedef struct
{
	union {
		uint32_t v[8];
		uint8_t c[32];
	} data;
} wpapsk_hash;

#ifndef CACHELINE_SIZE
#define CACHELINE_SIZE 64 // CPU L1 cache-line size, in bytes.
#endif

#define CACHELINE_PADDED_FIELD(T, name, length, cacheline_size)                \
	T name[(length)];                                                          \
	uint8_t name##_padding[(cacheline_size)                                    \
						   - ((length * sizeof(T)) % (cacheline_size))]

#pragma pack(push, 1)
/// Per-thread data needed by the crypto cracking engine.
struct ac_crypto_engine_perthread
{
	/// Holds the pair-wise master key.
	CACHELINE_PADDED_FIELD(wpapsk_hash,
						   pmk,
						   MAX_KEYS_PER_CRYPT_SUPPORTED,
						   CACHELINE_SIZE);

	/// Holds a 64-byte buffer for HMAC SHA1 ipad/opad, plus an extra 20-byte
	/// buffer for a SHA1 digest.
	CACHELINE_PADDED_FIELD(uint8_t,
						   hash1,
						   (64 + 20) * MAX_KEYS_PER_CRYPT_SUPPORTED,
						   CACHELINE_SIZE);

#ifndef AVX512F_FOUND
#define CRYPT_PADDING CACHELINE_SIZE / 2
#else
#define CRYPT_PADDING CACHELINE_SIZE
#endif
	/// Holds a 20-byte buffer for a SHA1 digest. Half cache-line size is to
	/// compact with the next.
	CACHELINE_PADDED_FIELD(uint8_t,
						   crypt1,
						   20 * MAX_KEYS_PER_CRYPT_SUPPORTED,
						   CRYPT_PADDING);

	/// Holds a 20-byte buffer for a SHA1 digest. Half cache-line size is to
	/// compact with the previous.
	CACHELINE_PADDED_FIELD(uint8_t,
						   crypt2,
						   20 * MAX_KEYS_PER_CRYPT_SUPPORTED,
						   CRYPT_PADDING);
#undef CRYPT_PADDING

	/// Holds a 20-byte buffer for a SHA1 digest. Double cache-line size is to
	/// space the next field futher out.
	CACHELINE_PADDED_FIELD(uint8_t,
						   ptk,
						   20 * MAX_KEYS_PER_CRYPT_SUPPORTED,
						   CACHELINE_SIZE * 2);

	/// Holds a 100-byte buffer for pair-wise key expansion.
	CACHELINE_PADDED_FIELD(uint8_t,
						   pke,
						   100 * MAX_KEYS_PER_CRYPT_SUPPORTED,
						   CACHELINE_SIZE);
};
#pragma pack(pop)
COMPILE_TIME_ASSERT((offsetof(struct ac_crypto_engine_perthread, pmk)) == 0);
COMPILE_TIME_ASSERT((offsetof(struct ac_crypto_engine_perthread, hash1)
					 % CACHELINE_SIZE)
					== 0);
COMPILE_TIME_ASSERT((offsetof(struct ac_crypto_engine_perthread, crypt1)
					 % CACHELINE_SIZE)
					== 0);
COMPILE_TIME_ASSERT((offsetof(struct ac_crypto_engine_perthread, crypt2)
					 % (CACHELINE_SIZE / 2))
					== 0);
COMPILE_TIME_ASSERT((offsetof(struct ac_crypto_engine_perthread, ptk)
					 % CACHELINE_SIZE)
					== 0);
COMPILE_TIME_ASSERT((offsetof(struct ac_crypto_engine_perthread, pke)
					 % CACHELINE_SIZE)
					== 0);

struct ac_crypto_engine
{
	uint8_t ** essid;
	uint32_t essid_length;

	struct ac_crypto_engine_perthread * thread_data[MAX_THREADS];
};

typedef struct ac_crypto_engine ac_crypto_engine_t;

/// The compiled-in features required to correctly execute on host.
IMPORT int ac_crypto_engine_supported_features(void);

/// global init. this could initialize threadid 1, but...
IMPORT int ac_crypto_engine_init(ac_crypto_engine_t * engine);
IMPORT void ac_crypto_engine_destroy(ac_crypto_engine_t * engine);

IMPORT void ac_crypto_engine_set_essid(ac_crypto_engine_t * engine,
									   const uint8_t * essid);

IMPORT uint8_t *
ac_crypto_engine_get_pmk(ac_crypto_engine_t * engine, int threadid, int index);

IMPORT uint8_t *
ac_crypto_engine_get_ptk(ac_crypto_engine_t * engine, int threadid, int index);

IMPORT void ac_crypto_engine_calc_pke(ac_crypto_engine_t * engine,
									  const uint8_t bssid[6],
									  const uint8_t stmac[6],
									  const uint8_t anonce[32],
									  const uint8_t snonce[32],
									  int threadid);

IMPORT void ac_crypto_engine_set_pmkid_salt(ac_crypto_engine_t * engine,
											const uint8_t bssid[6],
											const uint8_t stmac[6],
											int threadid);

/// per-thread-in-use init. separate to allow (possible) NUMA-local allocation.
IMPORT int ac_crypto_engine_thread_init(ac_crypto_engine_t * engine,
										int threadid);
IMPORT void ac_crypto_engine_thread_destroy(ac_crypto_engine_t * engine,
											int threadid);

/// acquire the width of simd we're compiled for.
IMPORT int ac_crypto_engine_simd_width(void);

IMPORT void ac_crypto_engine_calc_pmk(
	ac_crypto_engine_t * engine,
	const wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED],
	int nparallel,
	int threadid);

IMPORT void ac_crypto_engine_calc_ptk(ac_crypto_engine_t * engine,
									  const uint8_t keyver,
									  int vectorIdx,
									  int threadid);

IMPORT void ac_crypto_engine_calc_mic(ac_crypto_engine_t * engine,
									  const uint8_t eapol[256],
									  uint32_t eapol_size,
									  uint8_t mic[MAX_KEYS_PER_CRYPT_SUPPORTED]
												 [20],
									  uint8_t keyver,
									  int vectorIdx,
									  int threadid);

IMPORT int ac_crypto_engine_wpa_crack(
	ac_crypto_engine_t * engine,
	const wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED],
	const uint8_t eapol[256],
	uint32_t eapol_size,
	uint8_t mic[MAX_KEYS_PER_CRYPT_SUPPORTED][20],
	uint8_t keyver,
	const uint8_t cmpmic[20],
	int nparallel,
	int threadid);

IMPORT int ac_crypto_engine_wpa_pmkid_crack(
	ac_crypto_engine_t * engine,
	const wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED],
	const uint8_t pmkid[32],
	int nparallel,
	int threadid);

// Quick Utilities.

/// Calculate one pairwise master key, from the \a essid and \a key.
IMPORT void ac_crypto_engine_calc_one_pmk(const uint8_t * key,
										  const uint8_t * essid,
										  uint32_t essid_length,
										  uint8_t pmk[static PMK_LEN]);

#ifdef __cplusplus
}
#endif

#endif // AIRCRACK_NG_CRYPTO_ENGINE_H
