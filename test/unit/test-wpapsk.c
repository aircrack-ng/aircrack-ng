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
		= "\xd5\x35\x53\x82\xb8\xa9\xb8\x06\xdc\xaf\x99\xcd\xaf\x56\x4e\xb6";
	uint8_t stmac[6] = "\x00\x13\x46\xfe\x32\x0c";
	uint8_t snonce[32]
		= "\x59\x16\x8b\xc3\xa5\xdf\x18\xd7\x1e\xfb\x64\x23\xf3\x40\x08\x8d"
		  "\xab\x9e\x1b\xa2\xbb\xc5\x86\x59\xe0\x7b\x37\x64\xb0\xde\x85\x70";
	uint8_t anonce[32]
		= "\x22\x58\x54\xb0\x44\x4d\xe3\xaf\x06\xd1\x49\x2b\x85\x29\x84\xf0"
		  "\x4c\xf6\x27\x4c\x0e\x32\x18\xb8\x68\x17\x56\x86\x4d\xb7\xa0\x55";
	uint8_t eapol[256]
		= "\x01\x03\x00\x75\x02\x01\x0a\x00\x10\x00\x00\x00\x00\x00\x00\x00"
		  "\x01\x59\x16\x8b\xc3\xa5\xdf\x18\xd7\x1e\xfb\x64\x23\xf3\x40\x08"
		  "\x8d\xab\x9e\x1b\xa2\xbb\xc5\x86\x59\xe0\x7b\x37\x64\xb0\xde\x85"
		  "\x70\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		  "\x00\x00\x16\x30\x14\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac"
		  "\x04\x01\x00\x00\x0f\xac\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00"
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
	uint8_t bssid[6] = "\x00\x14\x6c\x7e\x40\x80";
	uint8_t essid[33] = "Harkonen";
	int nparallel = dso_ac_crypto_engine_simd_width();

	memset(&engine, 0, sizeof(engine));
	dso_ac_crypto_engine_init(&engine);
	dso_ac_crypto_engine_set_essid(&engine, &essid[0]);
	dso_ac_crypto_engine_thread_init(&engine, 1);
	dso_ac_crypto_engine_calc_pke(&engine, bssid, stmac, anonce, snonce, 1);

	for (int i = 0; i < nparallel; ++i)
	{
		int rc = -1;

		memset(key, 0, sizeof(key));

		strcpy((char *) (key[i].v), "12345678");
		key[i].length = 8;

		if ((rc = dso_ac_crypto_engine_wpa_crack(&engine,
												 key,
												 eapol,
												 eapol_size,
												 mic,
												 2,
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
			fail();
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
}
