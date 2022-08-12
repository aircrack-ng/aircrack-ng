# Aircrack-ng
#
# Copyright (C) 2019 Joseph Benden <joe@benden.us>
#
# Autotool support was written by: Joseph Benden <joe@benden.us>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
#
# In addition, as a special exception, the copyright holders give
# permission to link the code of portions of this program with the
# OpenSSL library under certain conditions as described in each
# individual source file, and distribute linked combinations
# including the two.
#
# You must obey the GNU General Public License in all respects
# for all of the code used other than OpenSSL.
#
# If you modify file(s) with this exception, you may extend this
# exception to your dnl version of the file(s), but you are not obligated
# to do so.
#
# If you dnl do not wish to do so, delete this exception statement from your
# version.
#
# If you delete this exception statement from all source files in the
# program, then also delete it here.

include %D%/osdep/Makefile.inc

SRC_CE_WEP	=	%D%/ce-wep/uniqueiv.c
SRC_CE_WPA	=	%D%/ce-wpa/crypto_engine.c \
							%D%/ce-wpa/memory.c \
							%D%/ce-wpa/simd-intrinsics.c \
							%D%/ce-wpa/wpapsk.c
SRC_COW			= %D%/cowpatty/cowpatty.c
SRC_CRYPTO	=	%D%/crypto/crypto.c
SRC_PTW			= %D%/ptw/aircrack-ptw-lib.c
SRC_LIBAC		= %D%/libac/adt/avl_tree.c \
							%D%/libac/adt/circular_buffer.c \
							%D%/libac/adt/circular_queue.c \
							%D%/libac/cpu/simd_cpuid.c \
							%D%/libac/support/fragments.c \
							%D%/libac/support/common.c \
							%D%/libac/support/communications.c \
							%D%/libac/support/crypto_engine_loader.c \
							%D%/libac/support/mcs_index_rates.c \
							%D%/libac/tui/console.c \
							%D%/libac/utf8/verifyssid.c
SRC_RADIOTAP = %D%/radiotap/radiotap.c

if LIBGCRYPT
SRC_CRYPTO	+=	%D%/crypto/sha1-git.c
endif

libaccrypto_la_SOURCES	= $(SRC_CRYPTO)
libaccrypto_la_CFLAGS		= $(COMMON_CFLAGS) $(PCRE_CFLAGS)
libaccrypto_la_LIBADD		= $(PCRE_LIBS) $(LIBAIRCRACK_OSDEP_LIBS) $(CRYPTO_LDFLAGS) $(CRYPTO_LIBS)

libcowpatty_la_SOURCES = $(SRC_COW)
libcowpatty_la_CFLAGS = $(COMMON_CFLAGS) $(LIBCOW_CFLAGS)
if !STATIC_CRYPTO
libcowpatty_la_LIBADD = $(COMMON_LDADD)
endif

libptw_la_SOURCES	= $(SRC_PTW)
libptw_la_CFLAGS	= $(COMMON_CFLAGS)
if !STATIC_CRYPTO
libptw_la_LIBADD	= $(COMMON_LDADD)
endif

libradiotap_la_SOURCES	= $(SRC_RADIOTAP)
libradiotap_la_LDFLAGS	= -no-undefined

########################################################################
# Aircrack Support Library                                             #
########################################################################

if ARM
TRAMPOLINE = %D%/libac/cpu/trampoline_arm.c
endif
if PPC
TRAMPOLINE = %D%/libac/cpu/trampoline_ppc.c
endif
if X86
TRAMPOLINE = %D%/libac/cpu/trampoline_x86.c
endif

if !ARM
if !PPC
if !X86
TRAMPOLINE = %D%/libac/cpu/trampoline_stubs.c
endif
endif
endif

if HAVE_HWLOC
CPUSET = %D%/libac/cpu/cpuset_hwloc.c
endif
if !HAVE_HWLOC
CPUSET = %D%/libac/cpu/cpuset_pthread.c
endif

if INCLUDE_COMPAT_STRLCAT
SRC_LIBAC += %D%/libac/support/strlcat.c
endif

if INCLUDE_COMPAT_STRLCPY
SRC_LIBAC += %D%/libac/support/strlcpy.c
endif

libaircrack_la_SOURCES	= $(SRC_LIBAC) $(TRAMPOLINE) $(CPUSET)
libaircrack_la_CFLAGS		= $(COMMON_CFLAGS) $(PCRE_CFLAGS) \
													"-DLIBAIRCRACK_CE_WPA_PATH=\"$(LIBAIRCRACK_CE_WPA_PATH)\"" \
													"-DABS_TOP_SRCDIR=\"$(abs_top_srcdir)\"" \
													"-DABS_TOP_BUILDDIR=\"$(abs_top_builddir)\"" \
													"-DLIBDIR=\"$(libdir)\""
libaircrack_la_LIBADD		= $(COMMON_LDADD) $(LIBAIRCRACK_OSDEP_LIBS) $(PCRE_LIBS) $(CRYPTO_LDFLAGS) $(CRYPTO_LIBS)

if CYGWIN
libaircrack_la_LIBADD += -lshlwapi
endif

if STATIC_BUILD
libaircrack_la_CFLAGS += -DSTATIC_BUILD
endif

if HAVE_HWLOC
libaircrack_la_CFLAGS += $(HWLOC_CFLAGS)
if !CYGWIN
if !STATIC_HWLOC
libaircrack_la_LIBADD += $(HWLOC_LIBS)
endif
endif
if CYGWIN
if !STATIC_HWLOC
libaircrack_la_LIBADD += $(HWLOC_LIBS)
endif
endif
endif

########################################################################
# Aircrack Crypto Engine for WEP                                       #
########################################################################

libaircrack_ce_wep_la_SOURCES	= $(SRC_CE_WEP)
libaircrack_ce_wep_la_CFLAGS	= $(COMMON_CFLAGS)
libaircrack_ce_wep_la_LIBADD	= $(CRYPTO_LDFLAGS) $(CRYPTO_LIBS)

########################################################################
# Aircrack Crypto Engine for WPA                                       #
########################################################################

# Intel/AMD
libaircrack_ce_wpa_x86_avx512_la_SOURCES = $(SRC_CE_WPA)
libaircrack_ce_wpa_x86_avx512_la_CFLAGS = $(x86_avx512_cflags) -DSIMD_CORE -DJOHN_AVX512F $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS)
libaircrack_ce_wpa_x86_avx512_la_LDFLAGS = -release $(LT_VER) -no-undefined
if !STATIC_CRYPTO
libaircrack_ce_wpa_x86_avx512_la_LIBADD = $(LIBACCRYPTO_LIBS) $(PTHREAD_LIBS) $(CRYPTO_LDFLAGS) $(CRYPTO_LIBS) $(ZLIB_LIBS)
endif

libaircrack_ce_wpa_x86_avx2_la_SOURCES = $(SRC_CE_WPA)
libaircrack_ce_wpa_x86_avx2_la_CFLAGS = $(x86_avx2_cflags) -DSIMD_CORE -DJOHN_AVX2 $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS)
libaircrack_ce_wpa_x86_avx2_la_LDFLAGS = -release $(LT_VER) -no-undefined
if !STATIC_CRYPTO
libaircrack_ce_wpa_x86_avx2_la_LIBADD = $(LIBACCRYPTO_LIBS) $(PTHREAD_LIBS) $(CRYPTO_LDFLAGS) $(CRYPTO_LIBS) $(ZLIB_LIBS)
endif

libaircrack_ce_wpa_x86_avx_la_SOURCES = $(SRC_CE_WPA)
libaircrack_ce_wpa_x86_avx_la_CFLAGS = $(x86_avx_cflags) -DSIMD_CORE -DJOHN_AVX $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS)
libaircrack_ce_wpa_x86_avx_la_LDFLAGS = -release $(LT_VER) -no-undefined
if !STATIC_CRYPTO
libaircrack_ce_wpa_x86_avx_la_LIBADD = $(LIBACCRYPTO_LIBS) $(PTHREAD_LIBS) $(CRYPTO_LDFLAGS) $(CRYPTO_LIBS) $(ZLIB_LIBS)
endif

libaircrack_ce_wpa_x86_sse2_la_SOURCES = $(SRC_CE_WPA)
libaircrack_ce_wpa_x86_sse2_la_CFLAGS = $(x86_sse2_cflags) -DSIMD_CORE -DJOHN_SSE2 $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS)
libaircrack_ce_wpa_x86_sse2_la_LDFLAGS = -release $(LT_VER) -no-undefined
if !STATIC_CRYPTO
libaircrack_ce_wpa_x86_sse2_la_LIBADD = $(LIBACCRYPTO_LIBS) $(PTHREAD_LIBS) $(CRYPTO_LDFLAGS) $(CRYPTO_LIBS) $(ZLIB_LIBS)
endif

# ARM/AARCH64
libaircrack_ce_wpa_arm_neon_la_SOURCES = $(SRC_CE_WPA)
libaircrack_ce_wpa_arm_neon_la_CFLAGS = $(arm_neon_cflags) -DSIMD_CORE -DHAS_NEON $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS)
libaircrack_ce_wpa_arm_neon_la_LDFLAGS = -release $(LT_VER) -no-undefined
if !STATIC_CRYPTO
libaircrack_ce_wpa_arm_neon_la_LIBADD = $(LIBACCRYPTO_LIBS) $(PTHREAD_LIBS) $(CRYPTO_LDFLAGS) $(CRYPTO_LIBS) $(ZLIB_LIBS)
endif

# PowerPC
libaircrack_ce_wpa_ppc_altivec_la_SOURCES = $(SRC_CE_WPA)
libaircrack_ce_wpa_ppc_altivec_la_CFLAGS = $(ppc_altivec_cflags) -DSIMD_CORE -DHAS_ALTIVEC=1 -DJOHN_ALTIVEC $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS)
libaircrack_ce_wpa_ppc_altivec_la_LDFLAGS = -release $(LT_VER) -no-undefined
if !STATIC_CRYPTO
libaircrack_ce_wpa_ppc_altivec_la_LIBADD = $(LIBACCRYPTO_LIBS) $(PTHREAD_LIBS) $(CRYPTO_LDFLAGS) $(CRYPTO_LIBS) $(ZLIB_LIBS)
endif

libaircrack_ce_wpa_ppc_power8_la_SOURCES = $(SRC_CE_WPA)
libaircrack_ce_wpa_ppc_power8_la_CFLAGS = $(ppc_altivec_cflags) -DSIMD_CORE -DHAS_ALTIVEC=1 -DJOHN_ALTIVEC -DJOHN_POWER8 $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS)
libaircrack_ce_wpa_ppc_power8_la_LDFLAGS = -release $(LT_VER) -no-undefined
if !STATIC_CRYPTO
libaircrack_ce_wpa_ppc_power8_la_LIBADD = $(LIBACCRYPTO_LIBS) $(PTHREAD_LIBS) $(CRYPTO_LDFLAGS) $(CRYPTO_LIBS) $(ZLIB_LIBS)
endif

# Generic library
libaircrack_ce_wpa_la_CFLAGS = $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS)
libaircrack_ce_wpa_la_SOURCES = $(SRC_CE_WPA)
libaircrack_ce_wpa_la_LDFLAGS = -release $(LT_VER) -no-undefined
if !STATIC_CRYPTO
libaircrack_ce_wpa_la_LIBADD = $(LIBACCRYPTO_LIBS) $(PTHREAD_LIBS) $(CRYPTO_LDFLAGS) $(CRYPTO_LIBS) $(ZLIB_LIBS)
endif

# Build librarie(s)
lib_LTLIBRARIES += libaircrack-ce-wpa.la

if ARM
if NEON
lib_LTLIBRARIES += libaircrack-ce-wpa-arm-neon.la
endif
endif
if PPC
if ALTIVEC
lib_LTLIBRARIES += libaircrack-ce-wpa-ppc-altivec.la
endif
if POWER8
lib_LTLIBRARIES += libaircrack-ce-wpa-ppc-power8.la
endif
endif
if X86
if AVX512F
lib_LTLIBRARIES += libaircrack-ce-wpa-x86-avx512.la
endif
lib_LTLIBRARIES += libaircrack-ce-wpa-x86-avx2.la libaircrack-ce-wpa-x86-avx.la libaircrack-ce-wpa-x86-sse2.la
endif

noinst_LTLIBRARIES += libaircrack-ce-wep.la libcowpatty.la libaccrypto.la libptw.la libaircrack.la libradiotap.la

EXTRA_DIST +=	%D%/ce-wep/uniqueiv.c \
							%D%/ce-wpa/crypto_engine.c \
							%D%/ce-wpa/memory.c \
							%D%/ce-wpa/simd-intrinsics.c \
							%D%/ce-wpa/wpapsk.c \
							%D%/cowpatty/cowpatty.c \
							%D%/crypto/crypto.c \
							%D%/crypto/sha1-git.c \
							%D%/libac/adt/avl_tree.c \
							%D%/libac/adt/circular_buffer.c \
							%D%/libac/adt/circular_queue.c \
							%D%/libac/cpu/cpuset_hwloc.c \
							%D%/libac/cpu/cpuset_pthread.c \
							%D%/libac/cpu/simd_cpuid.c \
							%D%/libac/cpu/trampoline_arm.c \
							%D%/libac/cpu/trampoline_ppc.c \
							%D%/libac/cpu/trampoline_stubs.c \
							%D%/libac/cpu/trampoline_x86.c \
							%D%/libac/support/common.c \
							%D%/libac/support/communications.c \
							%D%/libac/support/crypto_engine_loader.c \
							%D%/libac/support/fragments.c \
							%D%/libac/support/mcs_index_rates.c \
							%D%/libac/tui/console.c \
							%D%/libac/utf8/verifyssid.c \
							%D%/osdep/aircrack_ng_airpcap.h \
							%D%/osdep/airpcap.c \
							%D%/osdep/common.c \
							%D%/osdep/crctable_osdep.h \
							%D%/osdep/cygwin.c \
							%D%/osdep/cygwin.h \
							%D%/osdep/cygwin_tap.c \
							%D%/osdep/darwin.c \
							%D%/osdep/darwin_tap.c \
							%D%/osdep/dummy.c \
							%D%/osdep/dummy_tap.c \
							%D%/osdep/file.c \
							%D%/osdep/freebsd.c \
							%D%/osdep/freebsd_tap.c \
							%D%/osdep/linux.c \
							%D%/osdep/linux_tap.c \
							%D%/osdep/netbsd.c \
							%D%/osdep/netbsd_tap.c \
							%D%/osdep/network.c \
							%D%/osdep/openbsd.c \
							%D%/osdep/openbsd_tap.c \
							%D%/osdep/osdep.c \
							%D%/osdep/tap-win32/common.h \
							%D%/ptw/aircrack-ptw-lib.c \
							%D%/radiotap/COPYING \
							%D%/radiotap/parse.c \
							%D%/radiotap/platform.h \
							%D%/radiotap/radiotap.c \
							%D%/radiotap/radiotap.h \
							%D%/radiotap/radiotap_iter.h
