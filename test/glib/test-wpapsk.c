#include <glib.h>
#include <locale.h>

#include "aircrack-crypto/crypto_engine.h"

static void test_my_sanity(void) { g_assert_cmpint(1, ==, 1); }

static void test_calc_one_pmk(void)
{
	char essid[] = "linksys";
	char key[] = "password";
	uint8_t pmk[40] = {0};
	uint8_t expected[40] = {0xec, 0xc9, 0x99, 0x1e, 0x3c, 0xfb, 0x1b, 0x11,
							0x7b, 0xdb, 0xbd, 0x0,  0xde, 0xb4, 0x7,  0xf0,
							0x23, 0x29, 0x44, 0xb5, 0x68, 0x21, 0x64, 0x7e,
							0x23, 0x49, 0x13, 0x9d, 0x2,  0xfd, 0x2b, 0xfb,
							0x31, 0x83, 0x94, 0x12, 0x36, 0x89, 0x8e, 0xf7};

	memset(pmk, 0, sizeof(pmk));
	ac_crypto_engine_calc_one_pmk(key, essid, pmk);

	g_assert_cmpint(sizeof(pmk), ==, sizeof(expected));
	g_assert_cmpmem(pmk, sizeof(pmk), expected, sizeof(expected));
}

static void test_simd_can_crack(void)
{
	char key[128][MAX_THREADS];
	uint8_t pke[100];
	uint8_t ptk[8][80];
	uint8_t mic[8][20];
	uint8_t expected_mic[20] =
		"\xd5\x35\x53\x82\xb8\xa9\xb8\x06\xdc\xaf\x99\xcd\xaf\x56\x4e\xb6";
	uint8_t stmac[6] = "\x00\x13\x46\xfe\x32\x0c";
	uint8_t snonce[32] =
		"\x59\x16\x8b\xc3\xa5\xdf\x18\xd7\x1e\xfb\x64\x23\xf3\x40\x08\x8d"
		"\xab\x9e\x1b\xa2\xbb\xc5\x86\x59\xe0\x7b\x37\x64\xb0\xde\x85\x70";
	uint8_t anonce[32] =
		"\x22\x58\x54\xb0\x44\x4d\xe3\xaf\x06\xd1\x49\x2b\x85\x29\x84\xf0"
		"\x4c\xf6\x27\x4c\x0e\x32\x18\xb8\x68\x17\x56\x86\x4d\xb7\xa0\x55";
	uint8_t eapol[256] =
		"\x01\x03\x00\x75\x02\x01\x0a\x00\x10\x00\x00\x00\x00\x00\x00\x00"
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

	ac_crypto_engine_init(&engine);
	ac_crypto_engine_set_essid(&engine, (char *) essid);
	ac_crypto_engine_thread_init(&engine, 0);

	strcpy(key[0], "12345678");

	if (ac_crypto_engine_wpa_crack(&engine,
								   key,
								   pke,
								   eapol,
								   eapol_size,
								   ptk,
								   mic,
								   2,
								   expected_mic,
								   4,
								   0)
		< 0)
	{
		g_assert_true(0);
	}

	ac_crypto_engine_thread_destroy(&engine, 0);
	ac_crypto_engine_destroy(&engine);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "");

	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("https://github.com/aircrack-ng/aircrack-ng/issues/");

	// Define the tests.
	g_test_add_func("/sanity/test1", test_my_sanity);
	g_test_add_func("/scalar/calculates_one_pmk", test_calc_one_pmk);
	g_test_add_func("/simd/can_crack", test_simd_can_crack);

	return g_test_run();
}
