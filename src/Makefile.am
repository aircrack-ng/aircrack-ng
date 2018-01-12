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

NEWSSE=""
SIMDCORE=""

SRC_SSE_COMMON	= memory.c wpapsk.c

if NEWSSE
if SIMDCORE
CFLAGS		+= -DSIMD_CORE
SSEC_INT	= simd-intrinsics.c $(SRC_SSE_COMMON)
else
SSEC_INT	= sse-intrinsics.c $(SRC_SSE_COMMON)
endif
endif

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

SRC_AT		= airtun-ng.c
SRC_IV		= ivstools.c
SRC_AS		= airserv-ng.c
SRC_WS		= wesside-ng.c
SRC_BS		= besside-ng.c
SRC_BC		= besside-ng-crawler.c
SRC_AL		= airolib-ng.c
SRC_ES		= easside-ng.c
SRC_BUDDY	= buddy-ng.c
SRC_MI		= makeivs-ng.c
SRC_AB		= airbase-ng.c
SRC_AU		= airdecloak-ng.c
SRC_TT		= tkiptun-ng.c
SRC_WC		= wpaclean.c
SRC_AV		= airventriloquist-ng.c

SRC_ACLIB	= cpuid.c crypto.c common.c $(SSEC_INT) uniqueiv.c $(ASM_AC)
LIBAC	= libaclib.la
LIBAC_LIBS = libaclib.la

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

aircrack_ng_SOURCES = $(SRC_AC_ALL) $(SRC_LINECOUNT)
aircrack_ng_CFLAGS = $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS) $(SQLITE3_CFLAGS)
aircrack_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS) $(SQLITE3_LDFLAGS) $(LIBAC_LIBS) $(LIBPTW_LIBS)

airdecap_ng_SOURCES = $(SRC_AD)
airdecap_ng_CFLAGS = $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS)
airdecap_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBAC_LIBS)

packetforge_ng_SOURCES = $(SRC_PF)
packetforge_ng_CFLAGS = $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS)
packetforge_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBAC_LIBS)

aireplay_ng_SOURCES = $(SRC_AR) $(LIBOSD)
aireplay_ng_CFLAGS = $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(LIBNL_CFLAGS)
aireplay_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBOSD_LIBS) $(LIBNL_LIBS) $(LIBAC_LIBS)

airodump_ng_SOURCES = $(SRC_ADU) $(LIBOSD)
airodump_ng_CFLAGS = $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(PCRE_CFLAGS) $(LIBNL_CFLAGS)
airodump_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(PCRE_LIBS) $(LIBOSD_LIBS) $(LIBNL_LIBS) $(LIBAC_LIBS)

airserv_ng_SOURCES = $(SRC_AS) $(LIBOSD)
airserv_ng_CFLAGS = $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(LIBNL_CFLAGS)
airserv_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBOSD_LIBS) $(LIBNL_LIBS) $(LIBAC_LIBS)

airtun_ng_SOURCES = $(SRC_AT) $(LIBOSD)
airtun_ng_CFLAGS = $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(LIBNL_CFLAGS)
airtun_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBOSD_LIBS) $(LIBNL_LIBS) $(LIBAC_LIBS)

ivstools_SOURCES = $(SRC_IV)
ivstools_CFLAGS = $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS)
ivstools_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBAC_LIBS)

kstats_SOURCES = kstats.c
kstats_CFLAGS = $(PTHREAD_CFLAGS)
kstats_LDADD = $(PTHREAD_LIBS) $(LIBAC_LIBS)

wesside_ng_SOURCES = $(SRC_WS) $(LIBOSD)
wesside_ng_CFLAGS = $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS) $(LIBNL_CFLAGS)
wesside_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS) $(LIBOSD_LIBS) $(LIBNL_LIBS) $(LIBAC_LIBS) $(LIBPTW_LIBS)

easside_ng_SOURCES = $(SRC_ES) $(LIBOSD)
easside_ng_CFLAGS = $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS) $(LIBNL_CFLAGS)
easside_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS) $(LIBOSD_LIBS) $(LIBNL_LIBS) $(LIBAC_LIBS)

buddy_ng_SOURCES = $(SRC_BUDDY)
buddy_ng_CFLAGS = $(PTHREAD_CFLAGS)
buddy_ng_LDADD = $(PTHREAD_LIBS) $(LIBAC_LIBS)

besside_ng_SOURCES = $(SRC_BS) $(LIBOSD)
besside_ng_CFLAGS = $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS) $(PCRE_CFLAGS) $(LIBNL_CFLAGS)
besside_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS) $(PCRE_LIBS) $(LIBOSD_LIBS) $(LIBNL_LIBS) $(LIBAC_LIBS) $(LIBPTW_LIBS)

besside_ng_crawler_SOURCES = $(SRC_BC)
besside_ng_crawler_CFLAGS = $(PTHREAD_CFLAGS) $(PCAP_CFLAGS)
besside_ng_crawler_LDADD = $(PTHREAD_LIBS) $(PCAP_LIBS) $(LIBAC_LIBS)

makeivs_ng_SOURCES = $(SRC_MI)
makeivs_ng_CFLAGS = $(PTHREAD_CFLAGS)
makeivs_ng_LDADD = $(PTHREAD_LIBS) $(LIBAC_LIBS)

airolib_ng_SOURCES = $(SRC_AL)
airolib_ng_CFLAGS = $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(SQLITE3_CFLAGS) -DHAVE_REGEXP
airolib_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(SQLITE3_LDFLAGS) $(LIBAC_LIBS)

airbase_ng_SOURCES = $(SRC_AB) $(LIBOSD)
airbase_ng_CFLAGS = $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(LIBNL_CFLAGS)
airbase_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBOSD_LIBS) $(LIBNL_LIBS) $(LIBAC_LIBS)

airdecloak_ng_SOURCES = $(SRC_AU) $(LIBOSD)
airdecloak_ng_CFLAGS = $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS)
airdecloak_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBOSD_LIBS) $(LIBAC_LIBS)

tkiptun_ng_SOURCES = $(SRC_TT) $(LIBOSD)
tkiptun_ng_CFLAGS = $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(LIBNL_CFLAGS)
tkiptun_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBOSD_LIBS) $(LIBNL_LIBS) $(LIBAC_LIBS)

wpaclean_SOURCES = $(SRC_WC) $(LIBOSD)
wpaclean_CFLAGS = $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(LIBNL_CFLAGS)
wpaclean_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBOSD_LIBS) $(LIBNL_LIBS) $(LIBAC_LIBS)

airventriloquist_ng_SOURCES = $(SRC_AV) $(LIBOSD)
airventriloquist_ng_CFLAGS = $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(LIBNL_CFLAGS)
airventriloquist_ng_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBOSD_LIBS) $(LIBNL_LIBS) $(LIBAC_LIBS)

libaclib_la_SOURCES = $(SRC_ACLIB)
libaclib_la_CFLAGS = $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS)
libaclib_la_LIBADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS)

libptw_la_SOURCES = $(SRC_PTW)
libptw_la_CFLAGS = $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS)
libptw_la_LIBADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS)

noinst_LTLIBRARIES = libaclib.la libptw.la

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
             crypto.h 


@CODE_COVERAGE_RULES@
