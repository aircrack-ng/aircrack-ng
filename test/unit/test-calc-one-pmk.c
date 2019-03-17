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

#include "aircrack-ng/ce-wpa/crypto_engine.h"

static void test_calc_one_pmk(void ** state)
{
	(void) state;

	uint8_t essid[] = "linksys";
	uint8_t key[] = "password";
	uint8_t pmk[40] = {0};
	uint8_t expected[40]
		= {0xec, 0xc9, 0x99, 0x1e, 0x3c, 0xfb, 0x1b, 0x11, 0x7b, 0xdb,
		   0xbd, 0x0,  0xde, 0xb4, 0x7,  0xf0, 0x23, 0x29, 0x44, 0xb5,
		   0x68, 0x21, 0x64, 0x7e, 0x23, 0x49, 0x13, 0x9d, 0x2,  0xfd,
		   0x2b, 0xfb, 0x31, 0x83, 0x94, 0x12, 0x36, 0x89, 0x8e, 0xf7};

	memset(pmk, 0, sizeof(pmk));
	ac_crypto_engine_calc_one_pmk(key, essid, strlen((char *) essid), pmk);

	assert_int_equal(sizeof(pmk), sizeof(expected));
	assert_memory_equal(pmk, expected, sizeof(expected));
}

static void test_calc_pmk(void ** state)
{
	(void) state;

	uint8_t essid[33] = "linksys";
	wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED];
	ac_crypto_engine_t engine;

	memset(&engine, 0, sizeof(engine));
	ac_crypto_engine_init(&engine);
	ac_crypto_engine_set_essid(&engine, &essid[0]);
	ac_crypto_engine_thread_init(&engine, 1);

	memset(key, 0, sizeof(key));

	strcpy((char *) (key[0].v), "password");
	key[0].length = 8;

	ac_crypto_engine_calc_pmk(&engine, key, 1, 1);

	uint8_t expected[40]
		= {0xec, 0xc9, 0x99, 0x1e, 0x3c, 0xfb, 0x1b, 0x11, 0x7b, 0xdb,
		   0xbd, 0x0,  0xde, 0xb4, 0x7,  0xf0, 0x23, 0x29, 0x44, 0xb5,
		   0x68, 0x21, 0x64, 0x7e, 0x23, 0x49, 0x13, 0x9d, 0x2,  0xfd,
		   0x2b, 0xfb, 0x31, 0x83, 0x94, 0x12, 0x36, 0x89, 0x8e, 0xf7};

	assert_memory_equal((unsigned char *) (engine.thread_data[1]->pmk),
						expected,
						sizeof(expected));

	ac_crypto_engine_thread_destroy(&engine, 1);
	ac_crypto_engine_destroy(&engine);
}

int main(int argc, char * argv[])
{
	(void) argc;
	(void) argv;

	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_calc_one_pmk), cmocka_unit_test(test_calc_pmk),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
