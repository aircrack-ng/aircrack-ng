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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#ifndef STATIC_BUILD
#include <dlfcn.h>
#endif

#include "aircrack-crypto/crypto_engine.h"
#include "crypto_engine_loader.h"
#include "common.h"
#include "trampoline.h"

static void *module = NULL;

#ifdef STATIC_BUILD
int (*dso_ac_crypto_engine_init)(ac_crypto_engine_t *engine) =
	&ac_crypto_engine_init;
void (*dso_ac_crypto_engine_destroy)(ac_crypto_engine_t *engine) =
	&ac_crypto_engine_destroy;
void (*dso_ac_crypto_engine_set_essid)(ac_crypto_engine_t *engine,
									   const uint8_t *essid) =
	&ac_crypto_engine_set_essid;
int (*dso_ac_crypto_engine_thread_init)(
	ac_crypto_engine_t *engine, int threadid) = &ac_crypto_engine_thread_init;
void (*dso_ac_crypto_engine_thread_destroy)(
	ac_crypto_engine_t *engine, int threadid) = &ac_crypto_engine_thread_destroy;
int (*dso_ac_crypto_engine_simd_width)() = &ac_crypto_engine_simd_width;
int (*dso_ac_crypto_engine_wpa_crack)(
	ac_crypto_engine_t *engine,
	const wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED],
	const uint8_t eapol[256],
	uint32_t eapol_size,
	uint8_t mic[MAX_KEYS_PER_CRYPT_SUPPORTED][20],
	uint8_t keyver,
	const uint8_t cmpmic[20],
	int nparallel,
	int threadid) = &ac_crypto_engine_wpa_crack;
void (*dso_ac_crypto_engine_calc_pke)(ac_crypto_engine_t *engine,
									  const uint8_t bssid[6],
									  const uint8_t stmac[6],
									  const uint8_t anonce[32],
									  const uint8_t snonce[32],
									  int threadid) = &ac_crypto_engine_calc_pke;
int (*dso_ac_crypto_engine_supported_features)() =
	&ac_crypto_engine_supported_features;
#else
int (*dso_ac_crypto_engine_init)(ac_crypto_engine_t *engine) = NULL;
void (*dso_ac_crypto_engine_destroy)(ac_crypto_engine_t *engine) = NULL;
void (*dso_ac_crypto_engine_set_essid)(ac_crypto_engine_t *engine,
                                       const uint8_t *essid) = NULL;
int (*dso_ac_crypto_engine_thread_init)(ac_crypto_engine_t *engine,
                                        int threadid) = NULL;
void (*dso_ac_crypto_engine_thread_destroy)(ac_crypto_engine_t *engine,
                                            int threadid) = NULL;
int (*dso_ac_crypto_engine_simd_width)() = NULL;
int (*dso_ac_crypto_engine_wpa_crack)(
	ac_crypto_engine_t *engine,
	const wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED],
	const uint8_t eapol[256],
	uint32_t eapol_size,
	uint8_t mic[MAX_KEYS_PER_CRYPT_SUPPORTED][20],
	uint8_t keyver,
	const uint8_t cmpmic[20],
	int nparallel,
	int threadid) = NULL;
void (*dso_ac_crypto_engine_calc_pke)(ac_crypto_engine_t *engine,
                                      const uint8_t bssid[6],
                                      const uint8_t stmac[6],
                                      const uint8_t anonce[32],
                                      const uint8_t snonce[32],
                                      int threadid) = NULL;
int (*dso_ac_crypto_engine_supported_features)() = NULL;
#endif

// It must read the disk searching for the availables ones.
EXPORT int ac_crypto_engine_loader_get_available(void)
{
	int simd_flags = SIMD_SUPPORTS_NONE;
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
	if (!dsos) goto out;

	struct dirent *entry = NULL;
	while ((entry = readdir(dsos)) != NULL)
	{
#if defined(__APPLE__)
		if (string_has_suffix((char*) entry->d_name, ".dylib"))
#elif defined(WIN32) || defined(_WIN32)
		if (string_has_suffix((char*) entry->d_name, ".dll"))
#else
		if (string_has_suffix((char*) entry->d_name, ".so"))
#endif
		{
			char *search = strstr(entry->d_name, "aircrack-crypto-");

			if (search)
			{
				search += 16;
				simd_flags |= ac_crypto_engine_loader_string_to_flag(search);
			}
		}
	}

	closedir(dsos);

out:
	return simd_flags;
}

/// Caller must deallocate the returned pointer!
EXPORT char *ac_crypto_engine_loader_best_library_for(int simd_features)
{
	char buffer[8192] = {"aircrack-crypto"};
	char library_path[8192];
	char module_filename[8192];
	size_t buffer_remaining = 8192;

	if (simd_features & SIMD_SUPPORTS_AVX512F)
	{
		strncat(buffer, "-x86-avx512", buffer_remaining);
	}
	else if (simd_features & SIMD_SUPPORTS_AVX2)
	{
		strncat(buffer, "-x86-avx2", buffer_remaining);
	}
	else if (simd_features & SIMD_SUPPORTS_AVX)
	{
		strncat(buffer, "-x86-avx", buffer_remaining);
	}
	else if (simd_features & SIMD_SUPPORTS_SSE2)
	{
		strncat(buffer, "-x86-sse2", buffer_remaining);
	}
	else if (simd_features & SIMD_SUPPORTS_ASIMD)
	{
		strncat(buffer, "-arm-neon", buffer_remaining);
	}
	else if (simd_features & SIMD_SUPPORTS_NEON)
	{
		strncat(buffer, "-arm-neon", buffer_remaining);
	}
	else if (simd_features & SIMD_SUPPORTS_POWER8)
	{
		strncat(buffer, "-ppc-power8", buffer_remaining);
	}
	else if (simd_features & SIMD_SUPPORTS_ALTIVEC)
	{
		strncat(buffer, "-ppc-altivec", buffer_remaining);
	}

	char *working_directory = get_current_working_directory(); // or the binary's path?

	if (strncmp(working_directory, ABS_TOP_BUILDDIR, sizeof(ABS_TOP_BUILDDIR) - 1) == 0
	    || strncmp(working_directory, ABS_TOP_SRCDIR, sizeof(ABS_TOP_SRCDIR) - 1) == 0)
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

	snprintf(module_filename, sizeof(module_filename) - 1, "%s/%s%s.%s", library_path,
#if defined(WIN32) || defined(_WIN32)
		"",
#else
             "lib",
#endif
             buffer,
#if defined(WIN32) || defined(_WIN32)
		"dll"
#elif defined(__APPLE__)
		"dylib"
#else
             "so"
#endif
	);

	return strdup(module_filename);
}

EXPORT int ac_crypto_engine_loader_string_to_flag(const char *const str)
{
	int simd_features = SIMD_SUPPORTS_NONE;

	if (strncmp(str, "avx512", 6) == 0 || strncmp(str, "x86-avx512", 10) == 0)
		simd_features = SIMD_SUPPORTS_AVX512F;
	else if (strncmp(str, "avx2", 4) == 0 || strncmp(str, "x86-avx2", 8) == 0)
		simd_features = SIMD_SUPPORTS_AVX2;
	else if (strncmp(str, "avx", 3) == 0 || strncmp(str, "x86-avx", 7) == 0)
		simd_features = SIMD_SUPPORTS_AVX;
	else if (strncmp(str, "sse2", 4) == 0 || strncmp(str, "x86-sse2", 8) == 0)
		simd_features = SIMD_SUPPORTS_SSE2;
	else if (strncmp(str, "neon", 4) == 0 || strncmp(str, "arm-neon", 8) == 0)
		simd_features = SIMD_SUPPORTS_NEON;
	else if (strncmp(str, "asimd", 5) == 0 || strncmp(str, "arm-asimd", 9) == 0)
		simd_features = SIMD_SUPPORTS_ASIMD;
	else if (strncmp(str, "altivec", 7) == 0 || strncmp(str, "ppc-altivec", 11) == 0)
		simd_features = SIMD_SUPPORTS_ALTIVEC;
	else if (strncmp(str, "power8", 6) == 0 || strncmp(str, "ppc-power8", 10) == 0)
		simd_features = SIMD_SUPPORTS_POWER8;

	return simd_features;
}

/// Caller must NOT deallocate the returned pointer!
/// Caller must NOT use this function simultaneously between threads!
EXPORT char *ac_crypto_engine_loader_flags_to_string(int flags)
{
	char buffer[8192] = {0};

	if (flags & SIMD_SUPPORTS_AVX512F) strncat(buffer, "avx512 ", 7);
	if (flags & SIMD_SUPPORTS_AVX2) strncat(buffer, "avx2 ", 5);
	if (flags & SIMD_SUPPORTS_AVX) strncat(buffer, "avx ", 4);
	if (flags & SIMD_SUPPORTS_SSE2) strncat(buffer, "sse2 ", 5);
	if (flags & SIMD_SUPPORTS_NEON) strncat(buffer, "neon ", 5);
	if (flags & SIMD_SUPPORTS_ASIMD) strncat(buffer, "asimd ", 6);
	if (flags & SIMD_SUPPORTS_ALTIVEC) strncat(buffer, "altivec ", 8);
	if (flags & SIMD_SUPPORTS_POWER8) strncat(buffer, "power8 ", 7);

	strncat(buffer, "generic", 7);

	return strdup(buffer);
}

/// dlopen's and populates all DSO variables, but if not DYNAMIC these should be the addresses via static init.
EXPORT int ac_crypto_engine_loader_load(int flags)
{
#ifndef STATIC_BUILD
	if (flags == -1)
		flags = ac_crypto_engine_loader_get_available();

	char *module_filename = ac_crypto_engine_loader_best_library_for(flags);

	module = dlopen (module_filename, RTLD_LAZY);
	if (!module)
	{
		fprintf(stderr, "Could not open '%s'.\n", module_filename);
		free(module_filename);
		return 1;
	}
	free(module_filename);

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
		{ "ac_crypto_engine_supported_features", (void*)&dso_ac_crypto_engine_supported_features },

		{ NULL, NULL }
	};

	struct _dso_symbols *cur = &dso_symbols[0];

	for (; cur->addr != NULL; ++cur)
	{
		if (!(*((void**)cur->addr) = dlsym(module, cur->sym)))
		{
			fprintf(stderr, "Could not find symbol %s in %s.\n", cur->sym, module_filename);
			dlclose(module);
			return 1;
		}
	}
#endif

	return 0;
}

/// dlclose's and free's memory used
EXPORT void ac_crypto_engine_loader_unload(void)
{
#ifndef STATIC_BUILD
	dlclose(module);
	module = NULL;
#endif
}