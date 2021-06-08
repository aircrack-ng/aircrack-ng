/*
 * Copyright (C) 2018 Joseph Benden <joe@benden.us>
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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "aircrack-ng/crypto/crypto.h"
#include "aircrack-ng/support/common.h"
#include "aircrack-ng/cpu/trampoline.h"
#include "aircrack-ng/ce-wpa/crypto_engine.h"
#include "aircrack-ng/support/crypto_engine_loader.h"

/*
 * We must force linking to one of the support crypto libraries; however,
 * because they are linked with our binary and not the crypto engine
 * DSOs, at run-time we fail to run due to missing symbols.
 *
 * The "proper" way to handle this situation is to use --no-as-needed
 * linker flag, specifying the libraries to always link against.
 *
 * Then there is Autoconf... It does not support the above flag.
 *
 * So, we force a bit of hacks to ensure we do link against it.
 */
#ifdef USE_GCRYPT
void * keep_libgcrypt_ = (void *) ((uintptr_t) &gcry_md_open);
#else
void * keep_libcrypto_ = (void *) ((uintptr_t) &HMAC);
#endif

void perform_unit_testing(void ** state)
{
	(void) state;

	wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED];
	uint8_t mic[8][20];
	uint8_t expected_mic[20]
		= "\x2e\x13\xc4\x0c\xa1\xc2\xe4\xe2\x03\x7f\x99\xa2\xda\x18\xa4\x6b";
	uint8_t stmac[6] = "\x2c\xf0\xa2\xdd\xbc\xd0";
	uint8_t snonce[32]
		= "\x64\x67\x23\x3e\x73\x07\x67\xc3\x3e\x1d\xf8\x75\xc3\xad\x0e\xb5"
		  "\x8a\x51\xad\x70\x4a\x3f\xae\x06\xb8\x18\xc0\xc5\xfc\xeb\xf3\xaf";
	uint8_t anonce[32]
		= "\x02\x18\xc7\xb6\x4e\xce\xf4\x0c\x4f\x15\x91\x5f\xbc\xeb\x19\xc8"
		  "\xd6\x26\x08\x38\x7e\xb6\xb9\x86\xd9\x59\x9a\x8b\xd7\x0d\xc8\x5d";
	uint8_t eapol[256]
		= "\x02\x03\x00\x75\x02\x01\x0B\x00\x10\x00\x00\x00\x00\x00\x00\x00"
		  "\x03\x64\x67\x23\x3E\x73\x07\x67\xC3\x3E\x1D\xF8\x75\xC3\xAD\x0E"
		  "\xB5\x8A\x51\xAD\x70\x4A\x3F\xAE\x06\xB8\x18\xC0\xC5\xFC\xEB\xF3"
		  "\xAF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		  "\x00\x00\x16\x30\x14\x01\x00\x00\x0F\xAC\x04\x01\x00\x00\x0F\xAC"
		  "\x04\x01\x00\x00\x0F\xAC\x06\x8C\x00\x00\x00\x00\x00\x00\x00\x00"
		  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	uint32_t eapol_size = 121;
	ac_crypto_engine_t engine;
	uint8_t bssid[6] = "\xb0\xb9\x8a\x56\x8d\xea";
	uint8_t essid[33] = "Neheb";
	int nparallel = dso_ac_crypto_engine_simd_width();

	memset(&engine, 0, sizeof(engine));
	dso_ac_crypto_engine_init(&engine);
	dso_ac_crypto_engine_set_essid(&engine, &essid[0]);
	dso_ac_crypto_engine_thread_init(&engine, 1);
	dso_ac_crypto_engine_calc_pke(&engine, bssid, stmac, anonce, snonce, 1);

	// PMK: Ensure single calculator functions
	memset(key, 0, sizeof(key));
	strcpy((char *) (key[0].v), "bo$$password");
	key[0].length = 12;

	uint8_t pmk[40];
	memset(pmk, 0, sizeof(pmk));

	dso_ac_crypto_engine_calc_one_pmk(
		key[0].v, essid, strlen((char *) essid), pmk);
	assert_memory_equal(pmk,
						"\xfb\x57\x66\x8c\xd3\x38\x37\x44\x12\xc2\x62"
						"\x08\xd7\x9a\xa5\xc3\x0c\xe4\x0a\x11\x02\x24"
						"\xf3\xcf\xb5\x92\xa8\xf2\xe8\xbf\x53\xe8",
						32);

	// PMK: Ensure parallel calculator functions
	memset(key, 0, sizeof(key));
	strcpy((char *) (key[0].v), "bo$$password");
	key[0].length = 12;

	dso_ac_crypto_engine_calc_pmk(&engine, key, nparallel, 1);
	assert_memory_equal(dso_ac_crypto_engine_get_pmk(&engine, 1, 0),
						"\xfb\x57\x66\x8c\xd3\x38\x37\x44\x12\xc2\x62"
						"\x08\xd7\x9a\xa5\xc3\x0c\xe4\x0a\x11\x02\x24"
						"\xf3\xcf\xb5\x92\xa8\xf2\xe8\xbf\x53\xe8",
						32);

	for (int i = 0; i < nparallel; ++i)
	{
		int rc = -1;

		memset(key, 0, sizeof(key));

		strcpy((char *) (key[i].v), "bo$$password");
		key[i].length = 12;

		if ((rc = dso_ac_crypto_engine_wpa_crack(&engine,
												 key,
												 eapol,
												 eapol_size,
												 mic,
												 3,
												 expected_mic,
												 nparallel,
												 1))
			>= 0)
		{
			// does the returned SIMD lane equal where we placed the key?
			assert_int_equal(rc, i);
		}
		else
		{
			assert_memory_equal(dso_ac_crypto_engine_get_pmk(&engine, 1, i),
								"\xfb\x57\x66\x8c\xd3\x38\x37\x44\x12\xc2\x62"
								"\x08\xd7\x9a\xa5\xc3\x0c\xe4\x0a\x11\x02\x24"
								"\xf3\xcf\xb5\x92\xa8\xf2\xe8\xbf\x53\xe8",
								32);

			assert_memory_equal(dso_ac_crypto_engine_get_ptk(&engine, 1, i),
								"\x2c\x76\xdc\x59\x2c\x3b\x67\x1b\xac\x23\x0f"
								"\x6c\x9e\x38\xa0\x62\xa0\xdd\xc9\x8f\x4a\xb4"
								"\xd6\x12\x90\x22\xfc\x7f\x45\xfe\x92\x64",
								32);

			fail_msg("%s",
					 "While PMK and PTK computed correctly, MIC, etc. failed.");
		}
	}

	dso_ac_crypto_engine_thread_destroy(&engine, 1);
	dso_ac_crypto_engine_destroy(&engine);
}

void perform_unit_testing_for(void ** state, int simd_flag)
{
	int simd_features = (int) ((uintptr_t) *state);

	// load the DSO
	ac_crypto_engine_loader_load(simd_flag);

	// Check if this shared library CAN run on the machine, if not; skip testing it.
	if (simd_features < dso_ac_crypto_engine_supported_features())
	{
		// unit-test cannot run without an illegal instruction.
		skip();
	}
	else
	{
		// Perform the unit-testing; we can run without an illegal instruction exception.
		perform_unit_testing(state);
	}

#if !defined(SANITIZE_ADDRESS)
	ac_crypto_engine_loader_unload();
#endif
}

void test_crypto_engine_x86_avx512f(void ** state)
{
	perform_unit_testing_for(state, SIMD_SUPPORTS_AVX512F);
}

void test_crypto_engine_x86_avx2(void ** state)
{
	perform_unit_testing_for(state, SIMD_SUPPORTS_AVX2);
}

void test_crypto_engine_x86_avx(void ** state)
{
	perform_unit_testing_for(state, SIMD_SUPPORTS_AVX);
}

void test_crypto_engine_x86_sse2(void ** state)
{
	perform_unit_testing_for(state, SIMD_SUPPORTS_SSE2);
}

void test_crypto_engine_arm_neon(void ** state)
{
	perform_unit_testing_for(state, SIMD_SUPPORTS_NEON);
}

void test_crypto_engine_ppc_altivec(void ** state)
{
	perform_unit_testing_for(state, SIMD_SUPPORTS_ALTIVEC);
}

void test_crypto_engine_ppc_power8(void ** state)
{
	perform_unit_testing_for(state, SIMD_SUPPORTS_POWER8);
}

void test_crypto_engine_generic(void ** state)
{
	perform_unit_testing_for(state, SIMD_SUPPORTS_NONE);
}

int group_setup(void ** state)
{
	*state = (void *) ((uintptr_t) simd_get_supported_features());

	return 0;
}

int main(int argc, char * argv[])
{
	(void) argc;
	(void) argv;

#if defined(HAVE_OPENSSL_CMAC_H) || defined(GCRYPT_WITH_CMAC_AES)

	const struct CMUnitTest tests[]
		= { cmocka_unit_test(test_crypto_engine_generic),
#if defined(__x86_64__) || defined(__i386__) || defined(_M_IX86)
#if defined(__AVX512F__)
			cmocka_unit_test(test_crypto_engine_x86_avx512f),
#endif
			cmocka_unit_test(test_crypto_engine_x86_avx2),
			cmocka_unit_test(test_crypto_engine_x86_avx),
			cmocka_unit_test(test_crypto_engine_x86_sse2),
#elif defined(__arm) || defined(__aarch64) || defined(__aarch64__)
			cmocka_unit_test(test_crypto_engine_arm_neon),
#elif defined(__PPC__) || defined(__PPC64__)
			cmocka_unit_test(test_crypto_engine_ppc_altivec),
			cmocka_unit_test(test_crypto_engine_ppc_power8),
#else
/* warning "SIMD not available." */
#endif
		  };
	return cmocka_run_group_tests(tests, group_setup, NULL);

#else
	fprintf(stderr, "SKIP: Missing CMAC algorithm.\n");
	return 0;
#endif
}
