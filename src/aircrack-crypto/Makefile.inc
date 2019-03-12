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

LIBAIRCRACK_CRYPTO_SRCS = %D%/memory.c %D%/simd-intrinsics.c %D%/wpapsk.c %D%/crypto_engine.c

#
# Intel/AMD
#
libaircrack_crypto_x86_avx512_la_SOURCES = $(LIBAIRCRACK_CRYPTO_SRCS)
libaircrack_crypto_x86_avx512_la_CFLAGS = $(x86_avx512_cflags) -DSIMD_CORE -DJOHN_AVX512F $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS)
libaircrack_crypto_x86_avx512_la_LDFLAGS = -release 1.3.0 -no-undefined
if !STATIC_CRYPTO
libaircrack_crypto_x86_avx512_la_LIBADD = $(LIBACCRYPTO_LIBS) $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS)
endif

libaircrack_crypto_x86_avx2_la_SOURCES = $(LIBAIRCRACK_CRYPTO_SRCS)
libaircrack_crypto_x86_avx2_la_CFLAGS = $(x86_avx2_cflags) -DSIMD_CORE -DJOHN_AVX2 $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS)
libaircrack_crypto_x86_avx2_la_LDFLAGS = -release 1.3.0 -no-undefined
if !STATIC_CRYPTO
libaircrack_crypto_x86_avx2_la_LIBADD = $(LIBACCRYPTO_LIBS) $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS)
endif

libaircrack_crypto_x86_avx_la_SOURCES = $(LIBAIRCRACK_CRYPTO_SRCS)
libaircrack_crypto_x86_avx_la_CFLAGS = $(x86_avx_cflags) -DSIMD_CORE -DJOHN_AVX $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS)
libaircrack_crypto_x86_avx_la_LDFLAGS = -release 1.3.0 -no-undefined
if !STATIC_CRYPTO
libaircrack_crypto_x86_avx_la_LIBADD = $(LIBACCRYPTO_LIBS) $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS)
endif

libaircrack_crypto_x86_sse2_la_SOURCES = $(LIBAIRCRACK_CRYPTO_SRCS)
libaircrack_crypto_x86_sse2_la_CFLAGS = $(x86_sse2_cflags) -DSIMD_CORE -DJOHN_SSE2 $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS)
libaircrack_crypto_x86_sse2_la_LDFLAGS = -release 1.3.0 -no-undefined
if !STATIC_CRYPTO
libaircrack_crypto_x86_sse2_la_LIBADD = $(LIBACCRYPTO_LIBS) $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS)
endif

##
## ARM/AARCH64
##
libaircrack_crypto_arm_neon_la_SOURCES = $(LIBAIRCRACK_CRYPTO_SRCS)
libaircrack_crypto_arm_neon_la_CFLAGS = $(arm_neon_cflags) -DSIMD_CORE -DHAS_NEON $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS)
libaircrack_crypto_arm_neon_la_LDFLAGS = -release 1.3.0 -no-undefined
if !STATIC_CRYPTO
libaircrack_crypto_arm_neon_la_LIBADD = $(LIBACCRYPTO_LIBS) $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS)
endif

##
## PowerPC
##
libaircrack_crypto_ppc_altivec_la_SOURCES = $(LIBAIRCRACK_CRYPTO_SRCS)
libaircrack_crypto_ppc_altivec_la_CFLAGS = $(ppc_altivec_cflags) -DSIMD_CORE -DHAS_ALTIVEC=1 -DJOHN_ALTIVEC $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS)
libaircrack_crypto_ppc_altivec_la_LDFLAGS = -release 1.3.0 -no-undefined
if !STATIC_CRYPTO
libaircrack_crypto_ppc_altivec_la_LIBADD = $(LIBACCRYPTO_LIBS) $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS)
endif

libaircrack_crypto_ppc_power8_la_SOURCES = $(LIBAIRCRACK_CRYPTO_SRCS)
libaircrack_crypto_ppc_power8_la_CFLAGS = $(ppc_altivec_cflags) -DSIMD_CORE -DHAS_ALTIVEC=1 -DJOHN_ALTIVEC -DJOHN_POWER8 $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS)
libaircrack_crypto_ppc_power8_la_LDFLAGS = -release 1.3.0 -no-undefined
if !STATIC_CRYPTO
libaircrack_crypto_ppc_power8_la_LIBADD = $(LIBACCRYPTO_LIBS) $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS)
endif

#
# Generic library
libaircrack_crypto_la_CFLAGS = $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS)
libaircrack_crypto_la_SOURCES = %D%/memory.c %D%/wpapsk.c %D%/crypto_engine.c
libaircrack_crypto_la_LDFLAGS = -release 1.3.0 -no-undefined
if !STATIC_CRYPTO
libaircrack_crypto_la_LIBADD = $(LIBACCRYPTO_LIBS) $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS)
endif

#
# Build librarie(s)
#
lib_LTLIBRARIES += libaircrack-crypto.la

if ARM
if NEON
lib_LTLIBRARIES += libaircrack-crypto-arm-neon.la
endif
endif
if PPC
if ALTIVEC
lib_LTLIBRARIES += libaircrack-crypto-ppc-altivec.la
endif
if POWER8
lib_LTLIBRARIES += libaircrack-crypto-ppc-power8.la
endif
endif
if X86
if AVX512F
lib_LTLIBRARIES += libaircrack-crypto-x86-avx512.la
endif
lib_LTLIBRARIES += libaircrack-crypto-x86-avx2.la libaircrack-crypto-x86-avx.la libaircrack-crypto-x86-sse2.la
endif

EXTRA_DIST +=	%D%/aligned.h \
				%D%/arch.h \
				%D%/crypto_engine.c \
				%D%/crypto_engine.h \
				%D%/jcommon.h \
				%D%/johnswap.h \
				%D%/md5.h \
				%D%/MD5_std.h \
				%D%/memdbg.h \
				%D%/memory.c \
				%D%/memory.h \
				%D%/misc.h \
				%D%/pseudo_intrinsics.h \
				%D%/simd-intrinsics.c \
				%D%/simd-intrinsics.h \
				%D%/simd-intrinsics-load-flags.h \
				%D%/wpapsk.c \
				%D%/wpapsk.h
