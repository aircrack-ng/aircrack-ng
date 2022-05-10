/*
 *  Copyright (C) 2018-2022 Joseph Benden <joe@benden.us>
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

#ifndef AIRCRACK_NG_TRAMPOLINE_H
#define AIRCRACK_NG_TRAMPOLINE_H

#ifdef __cplusplus
extern "C" {
#endif

#define SIMD_SUPPORTS_NONE (1 << 0)
#define SIMD_SUPPORTS_MMX (1 << 1)
#define SIMD_SUPPORTS_SSE2 (1 << 2)
#define SIMD_SUPPORTS_AVX (1 << 3)
#define SIMD_SUPPORTS_AVX2 (1 << 4)
#define SIMD_SUPPORTS_NEON (1 << 5)
#define SIMD_SUPPORTS_ASIMD (1 << 6)
#define SIMD_SUPPORTS_ALTIVEC (1 << 7)
#define SIMD_SUPPORTS_POWER8 (1 << 8)
#define SIMD_SUPPORTS_AVX512F (1 << 9)

void simd_init(void);
int simd_get_supported_features(void);
void simd_destroy(void);

#ifdef __cplusplus
};
#endif

#endif
