/*
 *  Copyright (C) 2018 Joseph Benden <joe@benden.us>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(__i386__) || defined(__x86_64__)
#define _X86
#include <cpuid.h>
#else
#error "The wrong CPU architecture file has been included."
#endif

#include "aircrack-ng/cpu/trampoline.h"

void simd_init(void) {}

void simd_destroy(void) {}

int simd_get_supported_features(void)
{
	int result = 0;
	unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
	unsigned int max_level = __get_cpuid_max(0, 0);

	__cpuid(0, eax, ebx, ecx, edx);

	if (eax >= 1)
	{
		__cpuid(1, eax, ebx, ecx, edx);
	}

	if (edx & (1 << 23)) //-V525
	{
		result |= SIMD_SUPPORTS_MMX;
	}

	if (edx & (1 << 26))
	{
		result |= SIMD_SUPPORTS_SSE2;
	}

	if (ecx & (1 << 28))
	{
		result |= SIMD_SUPPORTS_AVX;
	}

	if (max_level >= 7)
	{
		__cpuid_count(7, 0, eax, ebx, ecx, edx);

		if (ebx & (1 << 16))
		{
			result |= SIMD_SUPPORTS_AVX512F;
		}

		if (ebx & (1 << 5))
		{
			result |= SIMD_SUPPORTS_AVX2;
		}
	}

	return (result);
}
