#include <glib.h>
#include <gmodule.h>
#include <locale.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "aircrack-crypto/crypto_engine.h"

static void test_my_sanity(void) { g_assert_cmpint(1, ==, 1); }

#if 0
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
	ac_crypto_engine_calc_one_pmk(key, essid, strlen(essid), pmk);

	g_assert_cmpint(sizeof(pmk), ==, sizeof(expected));
	g_assert_cmpmem(pmk, sizeof(pmk), expected, sizeof(expected));
}
#endif

static void test_simd_can_crack(gconstpointer test_data)
{
	char *entry = (char*) ((void*) test_data);

	// open it
	gchar *filename = g_strdup_printf("%s%s/%s", LIBAIRCRACK_CRYPTO_PATH, LT_OBJDIR, entry);
	GModule *module = g_module_open (filename, G_MODULE_BIND_LAZY);
	assert(module != NULL && "failed to open module");

	int (*dso_ac_crypto_engine_init)(ac_crypto_engine_t *engine);
	void (*dso_ac_crypto_engine_destroy)(ac_crypto_engine_t *engine);
	void (*dso_ac_crypto_engine_set_essid)(ac_crypto_engine_t *engine, const uint8_t *essid);
	int (*dso_ac_crypto_engine_thread_init)(ac_crypto_engine_t *engine, int threadid);
	void (*dso_ac_crypto_engine_thread_destroy)(ac_crypto_engine_t *engine, int threadid);
	int (*dso_ac_crypto_engine_simd_width)();

	int (*dso_ac_crypto_engine_wpa_crack)(ac_crypto_engine_t *engine, wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED], uint8_t eapol[256], uint32_t eapol_size, uint8_t mic[8][20], uint8_t keyver, const uint8_t cmpmic[20], int nparallel, int threadid);

	void (*dso_ac_crypto_engine_calc_pke)(ac_crypto_engine_t *engine, uint8_t bssid[6], uint8_t stmac[6], uint8_t anonce[32], uint8_t snonce[32], int threadid);

	// resolve symbols needed
	struct _dso_symbols
	{
	  char const *sym;
	  gpointer *addr;
	} dso_symbols[] = {
		{ "ac_crypto_engine_init", (gpointer *)&dso_ac_crypto_engine_init },
		{ "ac_crypto_engine_destroy", (gpointer *)&dso_ac_crypto_engine_destroy },
		{ "ac_crypto_engine_thread_init", (gpointer *)&dso_ac_crypto_engine_thread_init },
		{ "ac_crypto_engine_thread_destroy", (gpointer *)&dso_ac_crypto_engine_thread_destroy },
		{ "ac_crypto_engine_set_essid", (gpointer *)&dso_ac_crypto_engine_set_essid },
		{ "ac_crypto_engine_simd_width", (gpointer *)&dso_ac_crypto_engine_simd_width },
		{ "ac_crypto_engine_wpa_crack", (gpointer *)&dso_ac_crypto_engine_wpa_crack },
		{ "ac_crypto_engine_calc_pke", (gpointer *)&dso_ac_crypto_engine_calc_pke },

		{ NULL, NULL }
	};

	struct _dso_symbols *cur = &dso_symbols[0];

	for (; cur->addr != NULL; ++cur)
	{
		// fprintf(stdout, "Locating sym: %s\n", cur->sym);
		if (!g_module_symbol(module,
							 cur->sym,
							 cur->addr))
		{
			g_warning("%s: %s", filename, g_module_error());
			abort();
		}
	}

	g_assert_true(*dso_ac_crypto_engine_init);


	wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED];
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

		strcpy((char*) (key[i].v), "12345678");
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
			g_assert_cmpint(rc, ==, i);
		}
		else
		{
			g_assert_true(rc >= 0);
		}
	}

	dso_ac_crypto_engine_thread_destroy(&engine, 1);
	dso_ac_crypto_engine_destroy(&engine);


	// close it
	g_module_close(module);

	g_free(filename);
	g_free(entry);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "");

	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("https://github.com/aircrack-ng/aircrack-ng/issues/");

	// Define the tests.
	g_test_add_func("/sanity/test1", test_my_sanity);
	// g_test_add_func("/scalar/calculates_one_pmk", test_calc_one_pmk);

	// need passed in where DSO are.
	// fprintf(stdout, "Lib path: %s%s\n", LIBAIRCRACK_CRYPTO_PATH, LT_OBJDIR);

	// are we inside of the build path?
	gchar *working_directory = g_get_current_dir(); // or the binary's path?

	gchar *library_path = NULL;
	if (g_str_has_prefix(working_directory, ABS_TOP_BUILDDIR)
		|| g_str_has_prefix(working_directory, ABS_TOP_SRCDIR))
	{
		// use development paths
		library_path = g_strdup_printf("%s%s", LIBAIRCRACK_CRYPTO_PATH, LT_OBJDIR);
	}
	else
	{
		// use installation paths
		library_path = g_strdup_printf("%s", LIBDIR);
	}

	// enumerate all DSOs in folder, opening, searching symbols, and testing them.
	GDir *dsos = g_dir_open(library_path, 0, NULL);
	g_assert_true(dsos);
	g_free(library_path);

	gchar const *entry = NULL;
	while ((entry = g_dir_read_name(dsos)) != NULL)
	{
#if defined(__APPLE__)
		if (g_str_has_suffix(entry, ".dylib"))
#elif defined(WIN32) || defined(_WIN32)
		if (g_str_has_suffix(entry, ".dll"))
#else
		if (g_str_has_suffix(entry, ".so"))
#endif
		{
			// got an entry
			// fprintf(stdout, "Got: %s\n", entry);

			// test it
			gchar *test_case = g_strdup_printf("/simd/can_crack/%s", entry);
			g_test_add_data_func(test_case, (gconstpointer) ((void*) g_strdup(entry)), test_simd_can_crack);
			g_free(test_case);
		}
	}

	g_dir_close(dsos);

	return g_test_run();
}
