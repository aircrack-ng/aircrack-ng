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

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#ifndef STATIC_BUILD
#include <dlfcn.h>
#endif

#include "aircrack-ng/ce-wpa/crypto_engine.h"
#include "aircrack-ng/support/crypto_engine_loader.h"
#include "aircrack-ng/support/common.h"
#include "aircrack-ng/cpu/trampoline.h"

#ifndef STATIC_BUILD
static void * module = NULL;
#endif

#ifdef STATIC_BUILD
int (*dso_ac_crypto_engine_init)(ac_crypto_engine_t * engine)
	= &ac_crypto_engine_init;
void (*dso_ac_crypto_engine_destroy)(ac_crypto_engine_t * engine)
	= &ac_crypto_engine_destroy;
void (*dso_ac_crypto_engine_set_essid)(ac_crypto_engine_t * engine,
									   const uint8_t * essid)
	= &ac_crypto_engine_set_essid;
int (*dso_ac_crypto_engine_thread_init)(ac_crypto_engine_t * engine,
										int threadid)
	= &ac_crypto_engine_thread_init;
void (*dso_ac_crypto_engine_thread_destroy)(ac_crypto_engine_t * engine,
											int threadid)
	= &ac_crypto_engine_thread_destroy;
int (*dso_ac_crypto_engine_simd_width)(void) = &ac_crypto_engine_simd_width;
int (*dso_ac_crypto_engine_wpa_crack)(
	ac_crypto_engine_t * engine,
	const wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED],
	const uint8_t eapol[256],
	uint32_t eapol_size,
	uint8_t mic[MAX_KEYS_PER_CRYPT_SUPPORTED][20],
	uint8_t keyver,
	const uint8_t cmpmic[20],
	int nparallel,
	int threadid)
	= &ac_crypto_engine_wpa_crack;
void (*dso_ac_crypto_engine_calc_pke)(ac_crypto_engine_t * engine,
									  const uint8_t bssid[6],
									  const uint8_t stmac[6],
									  const uint8_t anonce[32],
									  const uint8_t snonce[32],
									  int threadid)
	= &ac_crypto_engine_calc_pke;
int (*dso_ac_crypto_engine_wpa_pmkid_crack)(
	ac_crypto_engine_t * engine,
	const wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED],
	const uint8_t pmkid[32],
	int nparallel,
	int threadid)
	= &ac_crypto_engine_wpa_pmkid_crack;
void (*dso_ac_crypto_engine_set_pmkid_salt)(ac_crypto_engine_t * engine,
											const uint8_t bssid[6],
											const uint8_t stmac[6],
											int threadid)
	= &ac_crypto_engine_set_pmkid_salt;
int (*dso_ac_crypto_engine_supported_features)(void)
	= &ac_crypto_engine_supported_features;
uint8_t * (*dso_ac_crypto_engine_get_pmk)(ac_crypto_engine_t * engine,
										  int threadid,
										  int index)
	= &ac_crypto_engine_get_pmk;
uint8_t * (*dso_ac_crypto_engine_get_ptk)(ac_crypto_engine_t * engine,
										  int threadid,
										  int index)
	= &ac_crypto_engine_get_ptk;
void (*dso_ac_crypto_engine_calc_one_pmk)(const uint8_t * key,
										  const uint8_t * essid,
										  uint32_t essid_length,
										  uint8_t pmk[40])
	= &ac_crypto_engine_calc_one_pmk;
void (*dso_ac_crypto_engine_calc_pmk)(
	ac_crypto_engine_t * engine,
	const wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED],
	int nparallel,
	int threadid)
	= &ac_crypto_engine_calc_pmk;
void (*dso_ac_crypto_engine_calc_mic)(ac_crypto_engine_t * engine,
									  const uint8_t eapol[256],
									  const uint32_t eapol_size,
									  uint8_t mic[MAX_KEYS_PER_CRYPT_SUPPORTED]
												 [20],
									  const uint8_t keyver,
									  const int vectorIdx,
									  const int threadid)
	= &ac_crypto_engine_calc_mic;
#else
int (*dso_ac_crypto_engine_init)(ac_crypto_engine_t * engine) = NULL;
void (*dso_ac_crypto_engine_destroy)(ac_crypto_engine_t * engine) = NULL;
void (*dso_ac_crypto_engine_set_essid)(ac_crypto_engine_t * engine,
									   const uint8_t * essid)
	= NULL;
int (*dso_ac_crypto_engine_thread_init)(ac_crypto_engine_t * engine,
										int threadid)
	= NULL;
void (*dso_ac_crypto_engine_thread_destroy)(ac_crypto_engine_t * engine,
											int threadid)
	= NULL;
int (*dso_ac_crypto_engine_simd_width)(void) = NULL;
int (*dso_ac_crypto_engine_wpa_crack)(
	ac_crypto_engine_t * engine,
	const wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED],
	const uint8_t eapol[256],
	uint32_t eapol_size,
	uint8_t mic[MAX_KEYS_PER_CRYPT_SUPPORTED][20],
	uint8_t keyver,
	const uint8_t cmpmic[20],
	int nparallel,
	int threadid)
	= NULL;
void (*dso_ac_crypto_engine_calc_pke)(ac_crypto_engine_t * engine,
									  const uint8_t bssid[6],
									  const uint8_t stmac[6],
									  const uint8_t anonce[32],
									  const uint8_t snonce[32],
									  int threadid)
	= NULL;
int (*dso_ac_crypto_engine_wpa_pmkid_crack)(
	ac_crypto_engine_t * engine,
	const wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED],
	const uint8_t pmkid[32],
	int nparallel,
	int threadid)
	= NULL;
void (*dso_ac_crypto_engine_set_pmkid_salt)(ac_crypto_engine_t * engine,
											const uint8_t bssid[6],
											const uint8_t stmac[6],
											int threadid)
	= NULL;
int (*dso_ac_crypto_engine_supported_features)(void) = NULL;
uint8_t * (*dso_ac_crypto_engine_get_pmk)(ac_crypto_engine_t * engine,
										  int threadid,
										  int index)
	= NULL;
uint8_t * (*dso_ac_crypto_engine_get_ptk)(ac_crypto_engine_t * engine,
										  int threadid,
										  int index)
	= NULL;
void (*dso_ac_crypto_engine_calc_one_pmk)(const uint8_t * key,
										  const uint8_t * essid,
										  uint32_t essid_length,
										  uint8_t pmk[40])
	= NULL;
void (*dso_ac_crypto_engine_calc_pmk)(
	ac_crypto_engine_t * engine,
	const wpapsk_password key[MAX_KEYS_PER_CRYPT_SUPPORTED],
	int nparallel,
	int threadid)
	= NULL;
void (*dso_ac_crypto_engine_calc_mic)(ac_crypto_engine_t * engine,
									  const uint8_t eapol[256],
									  const uint32_t eapol_size,
									  uint8_t mic[MAX_KEYS_PER_CRYPT_SUPPORTED]
												 [20],
									  const uint8_t keyver,
									  const int vectorIdx,
									  const int threadid)
	= NULL;
#endif

#if defined(WIN32_PORTABLE)
/*
	This is merely a hack until code refactoring can occur.

	A new module is needed for handling file and path operations, because
	this here is only a step towards correctly getting the executable
	path for all operating systems.

	It was required for Cygwin to determine the location of the
	Crypto Engine DLLs which are in the same folder as the
	executable.
*/
#include <stdarg.h>
#include <stdio.h>
#include <wtypes.h>
#include <wchar.h>
#include <sys/cygwin.h>

#include <windows.h>
#include <shlwapi.h>

static char * get_executable_directory(void)
{
	HMODULE hModule = GetModuleHandle(NULL);
	CHAR path[MAX_PATH];

	GetModuleFileNameA(hModule, path, MAX_PATH);
	PathRemoveFileSpecA(path);

	cygwin_conv_path_t flags = CCP_WIN_A_TO_POSIX;
	char * winpath = (char *) cygwin_create_path(flags, path);

	return winpath;
}
#endif

EXPORT int ac_crypto_engine_loader_get_available(void)
{
	int simd_flags = SIMD_SUPPORTS_NONE;
	char library_path[8192];

#if defined(WIN32_PORTABLE)
	char * working_directory = get_executable_directory();
#else
	// are we inside of the build path?
	char * working_directory = get_current_working_directory();
#endif
	REQUIRE(working_directory != NULL);

	if (strncmp(working_directory, ABS_TOP_BUILDDIR, strlen(ABS_TOP_BUILDDIR))
		== 0)
	{
		// use development paths
		snprintf(library_path,
				 sizeof(library_path) - 1,
				 "%s%s",
				 LIBAIRCRACK_CE_WPA_PATH,
				 LT_OBJDIR);
	}
	else
	{
#if defined(WIN32_PORTABLE)
		// use the current directory
		snprintf(library_path, sizeof(library_path) - 1, working_directory);
#else
		// use installation paths
		snprintf(library_path, sizeof(library_path) - 1, "%s", LIBDIR);
#endif
	}
	free(working_directory);

	// enumerate all DSOs in folder, opening, searching symbols, and testing
	// them.
	DIR * dsos = opendir(library_path);
	if (!dsos) goto out;

	struct dirent * entry = NULL;
	while ((entry = readdir(dsos)) != NULL)
	{
#if defined(__APPLE__)
		if (string_has_suffix((char *) entry->d_name, ".dylib"))
#elif defined(WIN32) || defined(_WIN32) || defined(CYGWIN)
		if (string_has_suffix((char *) entry->d_name, ".dll"))
#else
		if (string_has_suffix((char *) entry->d_name, ".so"))
#endif
		{
			char * search = strstr(entry->d_name, "aircrack-ce-wpa-");

			if (search)
			{
				search += 16;

				int flag;
				if ((flag = ac_crypto_engine_loader_string_to_flag(search))
					!= -1)
					simd_flags |= flag;
			}
		}
	}

	closedir(dsos);

out:
	return simd_flags;
}

EXPORT char * ac_crypto_engine_loader_best_library_for(int simd_features)
{
	char buffer[8192] = {"aircrack-ce-wpa"};
	char library_path[8192];
	char module_filename[8192];
	size_t buffer_remaining = 8192 - strlen(buffer) - 1;

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

	char * working_directory
		= get_current_working_directory(); // or the binary's path?
	REQUIRE(working_directory != NULL);

	if (strncmp(
			working_directory, ABS_TOP_BUILDDIR, sizeof(ABS_TOP_BUILDDIR) - 1)
		== 0)
	{
		// use development paths
		snprintf(library_path,
				 sizeof(library_path) - 1,
				 "%s%s",
				 LIBAIRCRACK_CE_WPA_PATH,
				 LT_OBJDIR);
	}
	else
	{
		// use installation paths
		snprintf(library_path, sizeof(library_path) - 1, "%s", LIBDIR);
	}
	free(working_directory);

#if defined(WIN32_PORTABLE)
#define LIB_FMT "%s%s%s"
#else
#define LIB_FMT "%s/%s%s%s", library_path
#endif

#if defined(WIN32) || defined(_WIN32) || defined(CYGWIN)
#if defined(MSYS2)
#define LIB_PREFIX "msys-"
#else
#define LIB_PREFIX "cyg"
#endif
#else
#define LIB_PREFIX "lib"
#endif

#if defined(WIN32) || defined(_WIN32) || defined(CYGWIN)
#define LIB_SUFFIX LT_CYGWIN_VER
#elif defined(__APPLE__)
#define LIB_SUFFIX ".dylib"
#else
#define LIB_SUFFIX ".so"
#endif

	snprintf(module_filename,
			 sizeof(module_filename) - 1,
			 LIB_FMT,
			 LIB_PREFIX,
			 buffer,
			 LIB_SUFFIX)
			< 0
		? abort()
		: (void) 0;

	return strdup(module_filename);
}

EXPORT int ac_crypto_engine_loader_string_to_flag(const char * const str)
{
	int simd_features = -1;

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
	else if (strncmp(str, "altivec", 7) == 0
			 || strncmp(str, "ppc-altivec", 11) == 0)
		simd_features = SIMD_SUPPORTS_ALTIVEC;
	else if (strncmp(str, "power8", 6) == 0
			 || strncmp(str, "ppc-power8", 10) == 0)
		simd_features = SIMD_SUPPORTS_POWER8;
	else if (strncmp(str, "generic", 7) == 0)
		simd_features = SIMD_SUPPORTS_NONE;

	return simd_features;
}

EXPORT char * ac_crypto_engine_loader_flags_to_string(int flags)
{
	char buffer[8192] = {0};

	if (flags & SIMD_SUPPORTS_AVX512F) strncat(buffer, "avx512 ", 8);
	if (flags & SIMD_SUPPORTS_AVX2) strncat(buffer, "avx2 ", 6);
	if (flags & SIMD_SUPPORTS_AVX) strncat(buffer, "avx ", 5);
	if (flags & SIMD_SUPPORTS_SSE2) strncat(buffer, "sse2 ", 6);
	if (flags & SIMD_SUPPORTS_NEON) strncat(buffer, "neon ", 6);
	if (flags & SIMD_SUPPORTS_ASIMD) strncat(buffer, "asimd ", 7);
	if (flags & SIMD_SUPPORTS_ALTIVEC) strncat(buffer, "altivec ", 9);
	if (flags & SIMD_SUPPORTS_POWER8) strncat(buffer, "power8 ", 8);

	strncat(buffer, "generic", 8);

	return strdup(buffer);
}

EXPORT int ac_crypto_engine_loader_load(int flags)
{
#ifndef STATIC_BUILD
	if (flags == -1) flags = ac_crypto_engine_loader_get_available();

	char * module_filename = ac_crypto_engine_loader_best_library_for(flags);
	REQUIRE(module_filename != NULL);

	module = dlopen(module_filename, RTLD_LAZY);
	if (!module)
	{
		const char * msg = dlerror();
		fprintf(stderr,
				"Could not open '%s': %s\n",
				module_filename,
				msg ? msg : "<none reported>");
		free(module_filename);
		return 1;
	}

	// resolve symbols needed
	struct _dso_symbols
	{
		char const * sym;
		void * addr;
	} dso_symbols[] = {
		{"ac_crypto_engine_init", (void *) &dso_ac_crypto_engine_init},
		{"ac_crypto_engine_destroy", (void *) &dso_ac_crypto_engine_destroy},
		{"ac_crypto_engine_thread_init",
		 (void *) &dso_ac_crypto_engine_thread_init},
		{"ac_crypto_engine_thread_destroy",
		 (void *) &dso_ac_crypto_engine_thread_destroy},
		{"ac_crypto_engine_set_essid",
		 (void *) &dso_ac_crypto_engine_set_essid},
		{"ac_crypto_engine_simd_width",
		 (void *) &dso_ac_crypto_engine_simd_width},
		{"ac_crypto_engine_wpa_crack",
		 (void *) &dso_ac_crypto_engine_wpa_crack},
		{"ac_crypto_engine_wpa_pmkid_crack",
		 (void *) &dso_ac_crypto_engine_wpa_pmkid_crack},
		{"ac_crypto_engine_calc_pke", (void *) &dso_ac_crypto_engine_calc_pke},
		{"ac_crypto_engine_set_pmkid_salt",
		 (void *) &dso_ac_crypto_engine_set_pmkid_salt},
		{"ac_crypto_engine_supported_features",
		 (void *) &dso_ac_crypto_engine_supported_features},
		{"ac_crypto_engine_get_pmk", (void *) &dso_ac_crypto_engine_get_pmk},
		{"ac_crypto_engine_get_ptk", (void *) &dso_ac_crypto_engine_get_ptk},
		{"ac_crypto_engine_calc_one_pmk",
		 (void *) &dso_ac_crypto_engine_calc_one_pmk},
		{"ac_crypto_engine_calc_pmk", (void *) &dso_ac_crypto_engine_calc_pmk},
		{"ac_crypto_engine_calc_mic", (void *) &dso_ac_crypto_engine_calc_mic},

		{NULL, NULL}};

	struct _dso_symbols * cur = &dso_symbols[0];

	for (; cur->addr != NULL; ++cur)
	{
		if (!(*((void **) cur->addr) = dlsym(module, cur->sym)))
		{
			fprintf(stderr,
					"Could not find symbol %s in %s.\n",
					cur->sym,
					module_filename);
			dlclose(module);
			free(module_filename);
			return 1;
		}
	}

	free(module_filename);
#else
	(void) flags;
#endif

	return 0;
}

EXPORT void ac_crypto_engine_loader_unload(void)
{
#ifndef STATIC_BUILD
	dlclose(module);
	module = NULL;

	dso_ac_crypto_engine_init = NULL;
	dso_ac_crypto_engine_destroy = NULL;
	dso_ac_crypto_engine_thread_init = NULL;
	dso_ac_crypto_engine_thread_destroy = NULL;
	dso_ac_crypto_engine_set_essid = NULL;
	dso_ac_crypto_engine_simd_width = NULL;
	dso_ac_crypto_engine_wpa_crack = NULL;
	dso_ac_crypto_engine_calc_pke = NULL;
	dso_ac_crypto_engine_supported_features = NULL;
#endif
}
