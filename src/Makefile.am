# Aircrack-ng
#
# Copyright (C) 2017 Joseph Benden <joe@benden.us>
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

SUBDIRS = include osdep

AM_CPPFLAGS = -I$(top_srcdir) \
              -I$(top_srcdir)/src/include \
              $(CRYPTO_INCLUDES)

SRC_LINECOUNT	= linecount.cpp
LIBLINECOUNT_LIBS = liblinecount.la

SRC_PTW		= aircrack-ptw-lib.c
LIBPTW_LIBS	= libptw.la

SRC_AC		= aircrack-ng.c
SRC_AC_ALL  = aircrack-ng.c
ASM_AC		= sha1-sse2.S

SRC_AD		= airdecap-ng.c
SRC_PF		= packetforge-ng.c
SRC_AR		= aireplay-ng.c
SRC_ADU		= airodump-ng.c

LIBMCS_LIBS	= libmcs.la
SRC_MCS		= mcs_index_rates.c

SRC_AT		= airtun-ng.c
SRC_IV		= ivstools.c
SRC_AS		= airserv-ng.c
SRC_WS		= wesside-ng.c
SRC_BS		= besside-ng.c
SRC_BC		= besside-ng-crawler.c
SRC_AL		= airolib-ng.c

LIBCOW_LIBS	= libcow.la
SRC_COW		= cowpatty.c

SRC_ES		= easside-ng.c
SRC_BUDDY	= buddy-ng.c
SRC_MI		= makeivs-ng.c
SRC_AB		= airbase-ng.c
SRC_AU		= airdecloak-ng.c
SRC_TT		= tkiptun-ng.c
SRC_WC		= wpaclean.c
SRC_AV		= airventriloquist-ng.c

SRC_SSE_COMMON	= memory.c wpapsk.c
LIBAC_CFLAGS = -DOLD_SSE_CORE=1
SRC_ACLIB	= cpuid.c crypto.c common.c $(SSEC_INT) uniqueiv.c $(ASM_AC)
LIBAC	= libaclib.la
LIBAC_LIBS = libaclib.la

AC_COMMON = cpuid.c crypto.c common.c $(SRC_SSE_COMMON) uniqueiv.c $(ASM_AC)

if LIBGCRYPT
SRC_AC		+= sha1-git.c
SRC_AC_ALL		+= sha1-git.c
SRC_ACLIB		+= sha1-git.c
SRC_AD		+= sha1-git.c
SRC_PF		+= sha1-git.c
SRC_IV		+= sha1-git.c
SRC_AR		+= sha1-git.c
SRC_ADU		+= sha1-git.c
SRC_AT		+= sha1-git.c
SRC_AB		+= sha1-git.c
SRC_AL		+= sha1-git.c
SRC_WS		+= sha1-git.c
SRC_TT		+= sha1-git.c
SRC_BS		+= sha1-git.c
SRC_AV		+= sha1-git.c
endif

LIBOSD		= osdep/libosdep.la
LIBOSD_LIBS	= -Losdep -losdep
if CYGWIN
LIBOSD_LIBS	+= -liphlpapi -lsetupapi -luuid
endif

pkglibexec_PROGRAMS = aircrack-ng--generic

if ARM
pkglibexec_PROGRAMS += aircrack-ng--neon \
                       aircrack-ng--asimd
endif

if PPC
pkglibexec_PROGRAMS += aircrack-ng--altivec \
                       aircrack-ng--power8
endif

if X86
pkglibexec_PROGRAMS += aircrack-ng--avx2 \
                       aircrack-ng--avx \
                       aircrack-ng--sse2
endif

bin_PROGRAMS = aircrack-ng \
               airdecap-ng \
               packetforge-ng \
               ivstools \
               kstats \
               makeivs-ng \
               airdecloak-ng

if HAVE_PCAP
bin_PROGRAMS += besside-ng-crawler
endif

bin_PROGRAMS += wpaclean

sbin_PROGRAMS = airventriloquist-ng \
                airbase-ng \
                aireplay-ng \
                airodump-ng \
                airserv-ng \
                airtun-ng

if HAVE_SQLITE3
bin_PROGRAMS += airolib-ng
endif

if EXPERIMENTAL
bin_PROGRAMS += buddy-ng

if HAVE_AIRPCAP_OR_PCAP
sbin_PROGRAMS += besside-ng \
                 easside-ng \
                 tkiptun-ng \
                 wesside-ng
endif
endif

aircrack_ng_SOURCES = trampoline.c trampoline.h
aircrack_ng_CFLAGS = "-DAIRCRACK_LIBEXEC_PATH=\"$(pkglibexecdir)\"" "-DEXEEXT=\"$(EXEEXT)\""
if ARM
aircrack_ng_SOURCES += trampoline_arm.c
endif
if PPC
aircrack_ng_SOURCES += trampoline_ppc.c
endif
if X86
aircrack_ng_SOURCES += trampoline_x86.c
endif
if !ARM
if !PPC
if !X86
aircrack_ng_SOURCES += trampoline_stubs.c
endif
endif
endif

aircrack_ng__generic_SOURCES = $(SRC_AC_ALL) $(SRC_LINECOUNT)
aircrack_ng__generic_CFLAGS = $(LIBAC_CFLAGS) $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS) $(SQLITE3_CFLAGS)
aircrack_ng__generic_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS) $(SQLITE3_LDFLAGS) $(LIBAC_LIBS) $(LIBPTW_LIBS)

#
# Intel/AMD
#
aircrack_ng__avx2_SOURCES = $(SRC_AC_ALL) $(SRC_LINECOUNT) simd-intrinsics.c $(AC_COMMON)
aircrack_ng__avx2_CFLAGS = $(x86_avx2_cflags) -DSIMD_CORE -DJOHN_AVX2 $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS) $(SQLITE3_CFLAGS)
aircrack_ng__avx2_CPPFLAGS = -I. $(AM_CPPFLAGS)
aircrack_ng__avx2_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS) $(SQLITE3_LDFLAGS) $(LIBPTW_LIBS)

aircrack_ng__avx_SOURCES = $(SRC_AC_ALL) $(SRC_LINECOUNT) simd-intrinsics.c $(AC_COMMON)
aircrack_ng__avx_CFLAGS = $(x86_avx_cflags) -DSIMD_CORE -DJOHN_AVX $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS) $(SQLITE3_CFLAGS)
aircrack_ng__avx_CPPFLAGS = -I. $(AM_CPPFLAGS)
aircrack_ng__avx_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS) $(SQLITE3_LDFLAGS) $(LIBPTW_LIBS)

aircrack_ng__sse2_SOURCES = $(SRC_AC_ALL) $(SRC_LINECOUNT) simd-intrinsics.c $(AC_COMMON)
aircrack_ng__sse2_CFLAGS = $(x86_sse2_cflags) -DSIMD_CORE $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS) $(SQLITE3_CFLAGS)
aircrack_ng__sse2_CPPFLAGS = -I. $(AM_CPPFLAGS)
aircrack_ng__sse2_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS) $(SQLITE3_LDFLAGS) $(LIBPTW_LIBS)

#
# ARM/AARCH64
#
aircrack_ng__neon_SOURCES = $(SRC_AC_ALL) $(SRC_LINECOUNT) simd-intrinsics.c $(AC_COMMON)
aircrack_ng__neon_CFLAGS = $(arm_neon_cflags) -DSIMD_CORE -DHAS_NEON $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS) $(SQLITE3_CFLAGS)
aircrack_ng__neon_CPPFLAGS = -I. $(AM_CPPFLAGS)
aircrack_ng__neon_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS) $(SQLITE3_LDFLAGS) $(LIBPTW_LIBS)

aircrack_ng__asimd_SOURCES = $(SRC_AC_ALL) $(SRC_LINECOUNT) simd-intrinsics.c $(AC_COMMON)
aircrack_ng__asimd_CFLAGS = $(arm_neon_cflags) -DSIMD_CORE -DHAS_NEON $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS) $(SQLITE3_CFLAGS)
aircrack_ng__asimd_CPPFLAGS = -I. $(AM_CPPFLAGS)
aircrack_ng__asimd_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS) $(SQLITE3_LDFLAGS) $(LIBPTW_LIBS)

#
# PowerPC
#
aircrack_ng__altivec_SOURCES = $(SRC_AC_ALL) $(SRC_LINECOUNT) simd-intrinsics.c $(AC_COMMON)
aircrack_ng__altivec_CFLAGS = $(ppc_altivec_cflags) -DSIMD_CORE -DHAS_ALTIVEC=1 -DJOHN_ALTIVEC $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS) $(SQLITE3_CFLAGS)
aircrack_ng__altivec_CPPFLAGS = -I. $(AM_CPPFLAGS)
aircrack_ng__altivec_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS) $(SQLITE3_LDFLAGS) $(LIBPTW_LIBS)

aircrack_ng__power8_SOURCES = $(SRC_AC_ALL) $(SRC_LINECOUNT) simd-intrinsics.c $(AC_COMMON)
aircrack_ng__power8_CFLAGS = $(ppc_altivec_cflags) -DSIMD_CORE -DHAS_ALTIVEC=1 -DJOHN_ALTIVEC $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS) $(SQLITE3_CFLAGS)
aircrack_ng__power8_CPPFLAGS = -I. $(AM_CPPFLAGS)
aircrack_ng__power8_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS) $(SQLITE3_LDFLAGS) $(LIBPTW_LIBS)

airdecap_ng_SOURCES = $(SRC_AD)
airdecap_ng_CFLAGS = $(LIBAC_CFLAGS) $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS)
airdecap_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBAC_LIBS)

packetforge_ng_SOURCES = $(SRC_PF)
packetforge_ng_CFLAGS = $(LIBAC_CFLAGS) $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS)
packetforge_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBAC_LIBS)

aireplay_ng_SOURCES = $(SRC_AR) $(LIBOSD)
aireplay_ng_CFLAGS = $(LIBAC_CFLAGS) $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(LIBNL_CFLAGS)
aireplay_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBOSD_LIBS) $(LIBNL_LIBS) $(LIBAC_LIBS) $(AIRPCAP_LIBS)

airodump_ng_SOURCES = $(SRC_ADU) $(LIBOSD) $(LIBMCS)
airodump_ng_CFLAGS = $(LIBAC_CFLAGS) $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(PCRE_CFLAGS) $(LIBNL_CFLAGS)
airodump_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(PCRE_LIBS) $(LIBOSD_LIBS) $(LIBNL_LIBS) $(LIBAC_LIBS) $(AIRPCAP_LIBS) $(LIBMCS_LIBS)

airserv_ng_SOURCES = $(SRC_AS) $(LIBOSD)
airserv_ng_CFLAGS = $(LIBAC_CFLAGS) $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(LIBNL_CFLAGS)
airserv_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBOSD_LIBS) $(LIBNL_LIBS) $(LIBAC_LIBS) $(AIRPCAP_LIBS)

airtun_ng_SOURCES = $(SRC_AT) $(LIBOSD)
airtun_ng_CFLAGS = $(LIBAC_CFLAGS) $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(LIBNL_CFLAGS)
airtun_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBOSD_LIBS) $(LIBNL_LIBS) $(LIBAC_LIBS) $(AIRPCAP_LIBS)

ivstools_SOURCES = $(SRC_IV)
ivstools_CFLAGS = $(LIBAC_CFLAGS) $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS)
ivstools_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBAC_LIBS)

kstats_SOURCES = kstats.c
kstats_CFLAGS = $(LIBAC_CFLAGS) $(PTHREAD_CFLAGS)
kstats_LDADD = $(PTHREAD_LIBS) $(LIBAC_LIBS)

wesside_ng_SOURCES = $(SRC_WS) $(LIBOSD)
wesside_ng_CFLAGS = $(LIBAC_CFLAGS) $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS) $(LIBNL_CFLAGS)
wesside_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS) $(LIBOSD_LIBS) $(LIBNL_LIBS) $(LIBAC_LIBS) $(LIBPTW_LIBS) $(AIRPCAP_LIBS)

easside_ng_SOURCES = $(SRC_ES) $(LIBOSD)
easside_ng_CFLAGS = $(LIBAC_CFLAGS) $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS) $(LIBNL_CFLAGS)
easside_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS) $(LIBOSD_LIBS) $(LIBNL_LIBS) $(LIBAC_LIBS) $(AIRPCAP_LIBS)

buddy_ng_SOURCES = $(SRC_BUDDY)
buddy_ng_CFLAGS = $(LIBAC_CFLAGS) $(PTHREAD_CFLAGS)
buddy_ng_LDADD = $(PTHREAD_LIBS) $(LIBAC_LIBS)

besside_ng_SOURCES = $(SRC_BS) $(LIBOSD)
besside_ng_CFLAGS = $(LIBAC_CFLAGS) $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS) $(PCRE_CFLAGS) $(LIBNL_CFLAGS)
besside_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS) $(PCRE_LIBS) $(LIBOSD_LIBS) $(LIBNL_LIBS) $(LIBAC_LIBS) $(LIBPTW_LIBS) $(AIRPCAP_LIBS)

besside_ng_crawler_SOURCES = $(SRC_BC)
besside_ng_crawler_CFLAGS = $(LIBAC_CFLAGS) $(PTHREAD_CFLAGS) $(PCAP_CFLAGS)
besside_ng_crawler_LDADD = $(PTHREAD_LIBS) $(PCAP_LIBS) $(LIBAC_LIBS)

makeivs_ng_SOURCES = $(SRC_MI)
makeivs_ng_CFLAGS = $(LIBAC_CFLAGS) $(PTHREAD_CFLAGS)
makeivs_ng_LDADD = $(PTHREAD_LIBS) $(LIBAC_LIBS)

airolib_ng_SOURCES = $(SRC_AL) $(LIBCOW)
airolib_ng_CFLAGS = $(LIBAC_CFLAGS) $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(SQLITE3_CFLAGS) -DHAVE_REGEXP
airolib_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(SQLITE3_LDFLAGS) $(LIBAC_LIBS) $(LIBCOW_LIBS)

airbase_ng_SOURCES = $(SRC_AB) $(LIBOSD)
airbase_ng_CFLAGS = $(LIBAC_CFLAGS) $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(LIBNL_CFLAGS)
airbase_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBOSD_LIBS) $(LIBNL_LIBS) $(LIBAC_LIBS) $(AIRPCAP_LIBS)

airdecloak_ng_SOURCES = $(SRC_AU) $(LIBOSD)
airdecloak_ng_CFLAGS = $(LIBAC_CFLAGS) $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS)
airdecloak_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBOSD_LIBS) $(LIBAC_LIBS) $(AIRPCAP_LIBS)

tkiptun_ng_SOURCES = $(SRC_TT) $(LIBOSD)
tkiptun_ng_CFLAGS = $(LIBAC_CFLAGS) $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(LIBNL_CFLAGS)
tkiptun_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBOSD_LIBS) $(LIBNL_LIBS) $(LIBAC_LIBS) $(AIRPCAP_LIBS)

wpaclean_SOURCES = $(SRC_WC) $(LIBOSD)
wpaclean_CFLAGS = $(LIBAC_CFLAGS) $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(LIBNL_CFLAGS)
wpaclean_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBOSD_LIBS) $(LIBNL_LIBS) $(LIBAC_LIBS) $(AIRPCAP_LIBS)

airventriloquist_ng_SOURCES = $(SRC_AV) $(LIBOSD)
airventriloquist_ng_CFLAGS = $(LIBAC_CFLAGS) $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(LIBNL_CFLAGS)
airventriloquist_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBOSD_LIBS) $(LIBNL_LIBS) $(LIBAC_LIBS) $(AIRPCAP_LIBS)

libaclib_la_SOURCES = $(SRC_ACLIB)
libaclib_la_CFLAGS = $(LIBAC_CFLAGS) $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS)
libaclib_la_LIBADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS)

libmcs_la_SOURCES = $(SRC_MCS)
libmcs_la_CFLAGS = $(LIBMCS_CFLAGS) $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS)
libmcs_la_LIBADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS)

libcow_la_SOURCES = $(SRC_COW)
libcow_la_CFLAGS = $(LIBCOW_CFLAGS) $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS)
libcow_la_LIBADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS)

libptw_la_SOURCES = $(SRC_PTW)
libptw_la_CFLAGS = $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS)
libptw_la_LIBADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS)

noinst_LTLIBRARIES = libaclib.la libptw.la libmcs.la libcow.la

EXTRA_DIST = wpaclean.c \
             buddy-ng.c \
             wpapsk.h \
             arch.h \
             aircrack-ng.h \
             version.h \
             airventriloquist-ng.h \
             airdecloak-ng.h \
             wpapsk.c \
             airserv-ng.c \
             common.c \
             simd-intrinsics-load-flags.h \
             besside-ng.c \
             wkp-frame.h \
             airolib-ng.c \
             simd-intrinsics.c \
             misc.h \
             aircrack-ptw-lib.h \
             simd-intrinsics.h \
             sha1-git.h \
             makeivs-ng.c \
             easside-ng.c \
             sse-intrinsics-load-flags.h \
             sha1-sse2.h \
             cpuid.c \
             pseudo_intrinsics.h \
             crctable.h \
             airdecap-ng.c \
             airodump-ng.h \
             airbase-ng.c \
             common.h \
             besside-ng-crawler.c \
             tkiptun-ng.c \
             kstats.c \
             md5.h \
             MD5_std.h \
             sse-intrinsics.h \
             easside.h \
             aireplay-ng.c \
             ivstools.c \
             pcap.h \
             aircrack-ng.c \
             airodump-ng.c \
             crypto.c \
             airdecloak-ng.c \
             memory.h \
             packetforge-ng.c \
             airventriloquist-ng.c \
             uniqueiv.c \
             gcrypt-openssl-wrapper.h \
             uniqueiv.h \
             wesside-ng.c \
             airtun-ng.c \
             aligned.h \
             johnswap.h \
             sha1-git.c \
             linecount.h \
             memdbg.h \
             sse-intrinsics.c \
             aircrack-ptw-lib.c \
             jcommon.h \
             memory.c \
             crypto.h \
             trampoline.c \
             trampoline.h \
             trampoline_x86.c \
             mcs_index_rates.c \
             mcs_index_rates.h \
             cowpatty.c \
             cowpatty.h 


@CODE_COVERAGE_RULES@
