# Aircrack-ng
#
# Copyright (C) 2018 Joseph Benden <joe@benden.us>
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
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

AM_CPPFLAGS = -I$(top_srcdir) \
              -I$(top_srcdir)/src/include \
              -I$(top_srcdir)/src \
              $(CRYPTO_INCLUDES) \
              $(GLIB_CFLAGS)

LIBAIRCRACK_CRYPTO_SRCS = memory.c sha1-git.c sha1-sse2.S simd-intrinsics.c wpapsk.c crypto_engine.c

#
# Intel/AMD
#
libaircrack_crypto_x86_avx2_la_SOURCES = $(LIBAIRCRACK_CRYPTO_SRCS)
libaircrack_crypto_x86_avx2_la_CFLAGS = $(x86_avx2_cflags) -DSIMD_CORE -DJOHN_AVX2 $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS)
#libaircrack_crypto_x86_avx2_la_CPPFLAGS = -I. $(AM_CPPFLAGS)
libaircrack_crypto_x86_avx2_la_LIBADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS)
libaircrack_crypto_x86_avx2_la_LDFLAGS = -version-info 0:0:0 -no-undefined

libaircrack_crypto_x86_avx_la_SOURCES = $(LIBAIRCRACK_CRYPTO_SRCS)
libaircrack_crypto_x86_avx_la_CFLAGS = $(x86_avx_cflags) -DSIMD_CORE -DJOHN_AVX $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS)
#libaircrack_crypto_x86_avx_la_CPPFLAGS = -I. $(AM_CPPFLAGS)
libaircrack_crypto_x86_avx_la_LIBADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS)
libaircrack_crypto_x86_avx_la_LDFLAGS = -version-info 0:0:0 -no-undefined

libaircrack_crypto_x86_sse2_la_SOURCES = $(LIBAIRCRACK_CRYPTO_SRCS)
libaircrack_crypto_x86_sse2_la_CFLAGS = $(x86_sse2_cflags) -DSIMD_CORE $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS)
#libaircrack_crypto_x86_sse2_la_CPPFLAGS = -I. $(AM_CPPFLAGS)
libaircrack_crypto_x86_sse2_la_LIBADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS)
libaircrack_crypto_x86_sse2_la_LDFLAGS = -version-info 0:0:0 -no-undefined

##
## ARM/AARCH64
##
#aircrack_ng__neon_SOURCES = $(SRC_AC_ALL) $(SRC_LINECOUNT) simd-intrinsics.c $(AC_COMMON) $(LIBAIRCRACK_UTIL)
#aircrack_ng__neon_CFLAGS = $(arm_neon_cflags) -DSIMD_CORE -DHAS_NEON $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS) $(SQLITE3_CFLAGS)
#aircrack_ng__neon_CPPFLAGS = -I. $(AM_CPPFLAGS)
#aircrack_ng__neon_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS) $(SQLITE3_LDFLAGS) $(LIBPTW_LIBS) $(LIBAIRCRACK_UTIL_LIBS)
#
#aircrack_ng__asimd_SOURCES = $(SRC_AC_ALL) $(SRC_LINECOUNT) simd-intrinsics.c $(AC_COMMON) $(LIBAIRCRACK_UTIL)
#aircrack_ng__asimd_CFLAGS = $(arm_neon_cflags) -DSIMD_CORE -DHAS_NEON $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS) $(SQLITE3_CFLAGS)
#aircrack_ng__asimd_CPPFLAGS = -I. $(AM_CPPFLAGS)
#aircrack_ng__asimd_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS) $(SQLITE3_LDFLAGS) $(LIBPTW_LIBS) $(LIBAIRCRACK_UTIL_LIBS)
#
##
## PowerPC
##
#aircrack_ng__altivec_SOURCES = $(SRC_AC_ALL) $(SRC_LINECOUNT) simd-intrinsics.c $(AC_COMMON) $(LIBAIRCRACK_UTIL)
#aircrack_ng__altivec_CFLAGS = $(ppc_altivec_cflags) -DSIMD_CORE -DHAS_ALTIVEC=1 -DJOHN_ALTIVEC $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS) $(SQLITE3_CFLAGS)
#aircrack_ng__altivec_CPPFLAGS = -I. $(AM_CPPFLAGS)
#aircrack_ng__altivec_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS) $(SQLITE3_LDFLAGS) $(LIBPTW_LIBS) $(LIBAIRCRACK_UTIL_LIBS)
#
#aircrack_ng__power8_SOURCES = $(SRC_AC_ALL) $(SRC_LINECOUNT) simd-intrinsics.c $(AC_COMMON) $(LIBAIRCRACK_UTIL)
#aircrack_ng__power8_CFLAGS = $(ppc_altivec_cflags) -DSIMD_CORE -DHAS_ALTIVEC=1 -DJOHN_ALTIVEC $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS) $(SQLITE3_CFLAGS)
#aircrack_ng__power8_CPPFLAGS = -I. $(AM_CPPFLAGS)
#aircrack_ng__power8_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS) $(SQLITE3_LDFLAGS) $(LIBPTW_LIBS) $(LIBAIRCRACK_UTIL_LIBS)

#
# Generic library
# -DOLD_SSE_CORE=1
libaircrack_crypto_la_CFLAGS = $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS)
libaircrack_crypto_la_SOURCES = memory.c sha1-git.c sha1-sse2.S sse-intrinsics.c wpapsk.c crypto_engine.c
libaircrack_crypto_la_LIBADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS)
libaircrack_crypto_la_LDFLAGS = -version-info 0:0:0 -no-undefined

#
# Build librarie(s)
#
lib_LTLIBRARIES = libaircrack-crypto.la

#if ARM
#lib_LTLIBRARIES += trampoline_arm.c
#endif
#if PPC
#lib_LTLIBRARIES += trampoline_ppc.c
#endif
if X86
lib_LTLIBRARIES += libaircrack-crypto-x86-avx2.la libaircrack-crypto-x86-avx.la libaircrack-crypto-x86-sse2.la
endif

EXTRA_DIST =	aligned.h \
				arch.h \
				crypto_engine.c \
				crypto_engine.h \
				jcommon.h \
				johnswap.h \
				md5.h \
				MD5_std.h \
				memdbg.h \
				memory.c \
				memory.h \
				misc.h \
				pseudo_intrinsics.h \
				sha1-git.c \
				sha1-git.h \
				sha1-sse2.h \
				sha1-sse2.S \
				simd-intrinsics.c \
				simd-intrinsics.h \
				simd-intrinsics-load-flags.h \
				sse-intrinsics.c \
				sse-intrinsics.h \
				sse-intrinsics-load-flags.h \
				wpapsk.c \
				wpapsk.h


@CODE_COVERAGE_RULES@
