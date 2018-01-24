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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#if defined(__arm__) || defined(__aarch64__)
#include <sys/auxv.h>
#include <asm/hwcap.h>
#else
#error "The wrong CPU architecture file has been included."
#endif

#include "trampoline.h"

void
simd_init (void)
{
}

void
simd_destroy (void)
{
}

int
simd_get_supported_features (void)
{
  int result = 0;
  long hwcaps = getauxval (AT_HWCAP);

#if defined(HWCAP_ASIMD)
  if (hwcaps & HWCAP_ASIMD)
  {
    result |= SIMD_SUPPORTS_ASIMD;
  }
#endif

#if defined(HWCAP_NEON)
  if (hwcaps & HWCAP_NEON)
  {
    result |= SIMD_SUPPORTS_NEON;
  }
#endif

  return (result);
}
