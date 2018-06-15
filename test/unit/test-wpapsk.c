#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <dlfcn.h>

#include "aircrack-util/common.h"
#include "aircrack-crypto/crypto_engine.h"

static void test_simd_can_crack(void* test_data)
{
	char library_path[8192];
	char module_filename[8192];
	char *entry = (char*) (test_data);

	int (*dso_ac_crypto_engine_init)(ac_crypto_engine_t *engine);
	void (*dso_ac_crypto_engine_destroy)(ac_crypto_engine_t *engine);
	void (*dso_ac_crypto_engine_set_essid)(ac_crypto_engine_t *engine, const uint8_t *essid);
	int (*dso_ac_crypto_engine_thread_init)(ac_crypto_engine_t *engine, int threadid);
	void (*dso_ac_crypto_engine_thread_destroy)(ac_crypto_engine_t *engine, int threadid);
	int (*dso_ac_crypto_engine_simd_width)();

	int (*dso_ac_crypto_engine_wpa_crack)(ac_crypto_engine_t *engine, wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED], uint8_t eapol[256], uint32_t eapol_size, uint8_t mic[8][20], uint8_t keyver, const uint8_t cmpmic[20], int nparallel, int threadid);

	void (*dso_ac_crypto_engine_calc_pke)(ac_crypto_engine_t *engine, uint8_t bssid[6], uint8_t stmac[6], uint8_t anonce[32], uint8_t snonce[32], int threadid);

	char *working_directory = get_current_working_directory();

	if (strncmp(working_directory, ABS_TOP_BUILDDIR, strlen(ABS_TOP_BUILDDIR)) == 0
	    || strncmp(working_directory, ABS_TOP_SRCDIR, strlen(ABS_TOP_SRCDIR)) == 0)
	{
		// use development paths
		snprintf(library_path, sizeof(library_path) - 1, "%s%s", LIBAIRCRACK_CRYPTO_PATH, LT_OBJDIR);
	}
	else
	{
		// use installation paths
		snprintf(library_path, sizeof(library_path) - 1, "%s", LIBDIR);
	}
	free(working_directory);

	snprintf(module_filename, sizeof(module_filename) - 1, "%s/%s", library_path, entry);

	void *module = dlopen (module_filename, RTLD_LAZY);
	assert_non_null(module);

	// resolve symbols needed
	struct _dso_symbols
	{
		char const *sym;
		void *addr;
	} dso_symbols[] = {
		{ "ac_crypto_engine_init", (void *)&dso_ac_crypto_engine_init },
		{ "ac_crypto_engine_destroy", (void *)&dso_ac_crypto_engine_destroy },
		{ "ac_crypto_engine_thread_init", (void *)&dso_ac_crypto_engine_thread_init },
		{ "ac_crypto_engine_thread_destroy", (void *)&dso_ac_crypto_engine_thread_destroy },
		{ "ac_crypto_engine_set_essid", (void *)&dso_ac_crypto_engine_set_essid },
		{ "ac_crypto_engine_simd_width", (void *)&dso_ac_crypto_engine_simd_width },
		{ "ac_crypto_engine_wpa_crack", (void *)&dso_ac_crypto_engine_wpa_crack },
		{ "ac_crypto_engine_calc_pke", (void *)&dso_ac_crypto_engine_calc_pke },

		{ NULL, NULL }
	};

	struct _dso_symbols *cur = &dso_symbols[0];

	for (; cur->addr != NULL; ++cur)
	{
		if (!(*((void**)cur->addr) = dlsym(module, cur->sym)))
		{
			fprintf(stderr, "Could not find symbol %s in %s.\n", cur->sym, module_filename);
			exit(1);
		}
	}

	assert_non_null(*dso_ac_crypto_engine_init);


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
			assert_int_equal(rc, i);
		}
		else
		{
			assert_true(rc >= 0);
		}
	}

	dso_ac_crypto_engine_thread_destroy(&engine, 1);
	dso_ac_crypto_engine_destroy(&engine);


	// close it
	dlclose(module);

	free(entry);
}

static void test_shared_library_can_crack(void **state)
{
	char library_path[8192];

	// are we inside of the build path?
	char *working_directory = get_current_working_directory();

	if (strncmp(working_directory, ABS_TOP_BUILDDIR, strlen(ABS_TOP_BUILDDIR)) == 0
	    || strncmp(working_directory, ABS_TOP_SRCDIR, strlen(ABS_TOP_SRCDIR)) == 0)
	{
		// use development paths
		snprintf(library_path, sizeof(library_path) - 1, "%s%s", LIBAIRCRACK_CRYPTO_PATH, LT_OBJDIR);
	}
	else
	{
		// use installation paths
		snprintf(library_path, sizeof(library_path) - 1, "%s", LIBDIR);
	}
	free(working_directory);


	// enumerate all DSOs in folder, opening, searching symbols, and testing them.
	DIR *dsos = opendir(library_path);
	assert_non_null(dsos);

	struct dirent *entry = NULL;
	while ((entry = readdir(dsos)) != NULL)
	{
#if defined(__APPLE__)
		if (g_str_has_suffix(entry, ".dylib"))
#elif defined(WIN32) || defined(_WIN32)
		if (g_str_has_suffix(entry, ".dll"))
#else
		if (string_has_suffix((char*) entry, ".so"))
#endif
		{
			// test it
			test_simd_can_crack(strdup(entry->d_name));
		}
	}

	closedir(dsos);
}

int main(int argc, char *argv[])
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_shared_library_can_crack),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
