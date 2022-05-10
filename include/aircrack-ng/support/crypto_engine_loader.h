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

#ifndef AIRCRACK_NG_CRYPTO_ENGINE_LOADER_H
#define AIRCRACK_NG_CRYPTO_ENGINE_LOADER_H

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

#define STATIC_ASSERT(COND, MSG)                                               \
	typedef char static_assertion_##MSG[(!!(COND)) * 2 - 1]
// token pasting madness:
#define COMPILE_TIME_ASSERT3(X, L)                                             \
	STATIC_ASSERT(X, static_assertion_at_line_##L)
#define COMPILE_TIME_ASSERT2(X, L) COMPILE_TIME_ASSERT3(X, L)
#define COMPILE_TIME_ASSERT(X) COMPILE_TIME_ASSERT2(X, __LINE__)

#if defined(__GNUC__) || defined(__llvm__) || defined(__clang__)               \
	|| defined(__INTEL_COMPILER)
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define likely(x) (x)
#define unlikely(x) (x)
#endif

#include <stdint.h>
#include <stddef.h>

#include <aircrack-ng/ce-wpa/crypto_engine.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Returns an integer bit representation of the available SIMD
 * Aircrack-ng Crypto Engine modules for the runtime machine.
 *
 * @return Integer bit representation of SIMD flags.
 */
IMPORT int ac_crypto_engine_loader_get_available(void);

/**
 * Returns an absolute path to the best Aircrack-ng Crypto
 * library to load. The caller \b MUST deallocate the
 * returned memory using \a free!
 *
 * @param simd_features Integer bit representation of SIMD flags.
 * @return character sequence that must be deallocated by caller.
 */
IMPORT char * ac_crypto_engine_loader_best_library_for(int simd_features);

/// Produces an integer bit representation of a SIMD character sequence.
IMPORT int ac_crypto_engine_loader_string_to_flag(const char * const str);

/**
 * Produces a character representation of the SIMD integer flags.
 *
 * All selected bits of \a flags are converted; producing a space
 * separated string representation.
 *
 * Caller \b MUST deallocate the returned value using \a free
 *
 * @param flags Integer bit representation of SIMD flags.
 * @return character sequence that must be deallocated by caller.
 */
IMPORT char * ac_crypto_engine_loader_flags_to_string(int flags);

/// Loads the specified Aircrack-ng Crypto Engine specified by \a flags.
/// Does nothing in a static build.
IMPORT int ac_crypto_engine_loader_load(int flags);

/// Unloads the Aircrack-ng Crypto Engine. Does nothing in a static build.
IMPORT void ac_crypto_engine_loader_unload(void);

// Symbols defined by the loader.

extern int (*dso_ac_crypto_engine_init)(ac_crypto_engine_t * engine);
extern void (*dso_ac_crypto_engine_destroy)(ac_crypto_engine_t * engine);
extern void (*dso_ac_crypto_engine_set_essid)(ac_crypto_engine_t * engine,
											  const uint8_t * essid);
extern int (*dso_ac_crypto_engine_thread_init)(ac_crypto_engine_t * engine,
											   int threadid);
extern void (*dso_ac_crypto_engine_thread_destroy)(ac_crypto_engine_t * engine,
												   int threadid);
extern int (*dso_ac_crypto_engine_simd_width)(void);
extern int (*dso_ac_crypto_engine_wpa_crack)(
	ac_crypto_engine_t * engine,
	const wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED],
	const uint8_t eapol[256],
	uint32_t eapol_size,
	uint8_t mic[MAX_KEYS_PER_CRYPT_SUPPORTED][20],
	uint8_t keyver,
	const uint8_t cmpmic[20],
	int nparallel,
	int threadid);
extern int (*dso_ac_crypto_engine_wpa_pmkid_crack)(
	ac_crypto_engine_t * engine,
	const wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED],
	const uint8_t pmkid[32],
	int nparallel,
	int threadid);
extern void (*dso_ac_crypto_engine_set_pmkid_salt)(ac_crypto_engine_t * engine,
												   const uint8_t bssid[6],
												   const uint8_t stmac[6],
												   int threadid);
extern void (*dso_ac_crypto_engine_calc_pke)(ac_crypto_engine_t * engine,
											 const uint8_t bssid[6],
											 const uint8_t stmac[6],
											 const uint8_t anonce[32],
											 const uint8_t snonce[32],
											 int threadid);
extern int (*dso_ac_crypto_engine_supported_features)(void);
extern uint8_t * (*dso_ac_crypto_engine_get_pmk)(ac_crypto_engine_t * engine,
												 int threadid,
												 int index);
extern uint8_t * (*dso_ac_crypto_engine_get_ptk)(ac_crypto_engine_t * engine,
												 int threadid,
												 int index);
extern void (*dso_ac_crypto_engine_calc_one_pmk)(const uint8_t * key,
												 const uint8_t * essid,
												 uint32_t essid_length,
												 uint8_t pmk[40]);
extern void (*dso_ac_crypto_engine_calc_pmk)(
	ac_crypto_engine_t * engine,
	const wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED],
	int nparallel,
	int threadid);
extern void (*dso_ac_crypto_engine_calc_mic)(
	ac_crypto_engine_t * engine,
	const uint8_t eapol[256],
	const uint32_t eapol_size,
	uint8_t mic[MAX_KEYS_PER_CRYPT_SUPPORTED][20],
	const uint8_t keyver,
	const int vectorIdx,
	const int threadid);

// End symbols defined by the loader.

#ifdef __cplusplus
}
#endif

#endif // AIRCRACK_NG_CRYPTO_ENGINE_LOADER_H
