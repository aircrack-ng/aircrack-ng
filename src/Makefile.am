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

SUBDIRS = aircrack-crypto aircrack-util include aircrack-osdep

AM_CPPFLAGS = -I$(top_srcdir) \
              -I$(top_srcdir)/src/include \
              $(CRYPTO_INCLUDES)

SRC_LINECOUNT	= linecount.cpp
LIBLINECOUNT_LIBS = liblinecount.la

SRC_PTW		= aircrack-ptw-lib.c
LIBPTW_LIBS	= libptw.la

SRC_AC		= aircrack-ng.c
SRC_AC_ALL  = aircrack-ng.c

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

SRC_ACLIB	= crypto.c $(SSEC_INT) uniqueiv.c session.c
LIBAC	= libaclib.la
LIBAC_LIBS = libaclib.la

AC_COMMON = crypto.c uniqueiv.c session.c

if LIBGCRYPT
SRC_AC          += sha1-git.c
SRC_AC_ALL              += sha1-git.c
SRC_ACLIB               += sha1-git.c
SRC_AD          += sha1-git.c
SRC_PF          += sha1-git.c
SRC_IV          += sha1-git.c
SRC_AR          += sha1-git.c
SRC_ADU         += sha1-git.c
SRC_AT          += sha1-git.c
SRC_AB          += sha1-git.c
SRC_AL          += sha1-git.c
SRC_WS          += sha1-git.c
SRC_TT          += sha1-git.c
SRC_BS          += sha1-git.c
SRC_AV          += sha1-git.c
endif

LIBAIRCRACK_CRYPTO = aircrack-crypto/libaircrack-crypto.la
LIBAIRCRACK_CRYPTO_LIBS = -Laircrack-crypto -laircrack-crypto

LIBAIRCRACK_CRYPTO_X86_AVX2 = aircrack-crypto/libaircrack-crypto-x86-avx2.la
LIBAIRCRACK_CRYPTO_X86_AVX2_LIBS = -Laircrack-crypto -laircrack-crypto-x86-avx2

LIBAIRCRACK_CRYPTO_X86_AVX = aircrack-crypto/libaircrack-crypto-x86-avx.la
LIBAIRCRACK_CRYPTO_X86_AVX_LIBS = -Laircrack-crypto -laircrack-crypto-x86-avx

LIBAIRCRACK_CRYPTO_X86_SSE2 = aircrack-crypto/libaircrack-crypto-x86-sse2.la
LIBAIRCRACK_CRYPTO_X86_SSE2_LIBS = -Laircrack-crypto -laircrack-crypto-x86-sse2

LIBAIRCRACK_UTIL = aircrack-util/libaircrack-util.la
LIBAIRCRACK_UTIL_LIBS = -Laircrack-util -laircrack-util

LIBAIRCRACK_OSDEP		= aircrack-osdep/libaircrack-osdep.la
LIBAIRCRACK_OSDEP_LIBS	= -Laircrack-osdep -laircrack-osdep
if CYGWIN
LIBAIRCRACK_OSDEP_LIBS	+= -liphlpapi -lsetupapi -luuid
endif

COMMON_CFLAGS = $(LIBAC_CFLAGS) $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS)
COMMON_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(ZLIB_LIBS)

bin_PROGRAMS = aircrack-ng \
               airdecap-ng \
               packetforge-ng \
               ivstools \
               kstats \
               makeivs-ng \
               airdecloak-ng

if EXPERIMENTAL
if HAVE_PCAP
bin_PROGRAMS += besside-ng-crawler
endif
endif

bin_PROGRAMS += wpaclean

sbin_PROGRAMS = airbase-ng \
                aireplay-ng \
                airodump-ng \
                airserv-ng \
                airtun-ng

if HAVE_SQLITE3
bin_PROGRAMS += airolib-ng
endif

if EXPERIMENTAL
bin_PROGRAMS += buddy-ng

sbin_PROGRAMS += airventriloquist-ng

if HAVE_AIRPCAP_OR_PCAP
sbin_PROGRAMS += besside-ng \
                 easside-ng \
                 tkiptun-ng \
                 wesside-ng
endif
endif

aircrack_ng_SOURCES = $(SRC_AC_ALL) $(SRC_LINECOUNT) $(LIBAIRCRACK_UTIL)
aircrack_ng_CFLAGS = $(COMMON_CFLAGS) $(SQLITE3_CFLAGS) $(LIBPTW_CFLAGS)
aircrack_ng_LDADD = $(LIBAIRCRACK_UTIL_LIBS) $(LIBAC_LIBS) $(SQLITE3_LDFLAGS) $(LIBPTW_LIBS) $(COMMON_LDADD) $(CRYPTO_LIBS) $(HWLOC_LIBS)

if STATIC_BUILD
aircrack_ng_CFLAGS += -DDYNAMIC=0
aircrack_ng_LDADD += $(LIBAIRCRACK_CRYPTO@SIMD_SUFFIX@_LIBS)
else
aircrack_ng_LDFLAGS = -rdynamic
endif

airdecap_ng_SOURCES = $(SRC_AD) $(LIBAIRCRACK_UTIL)
airdecap_ng_CFLAGS = $(COMMON_CFLAGS)
airdecap_ng_LDADD = $(COMMON_LDADD) $(LIBAC_LIBS) $(LIBAIRCRACK_UTIL_LIBS) $(CRYPTO_LIBS)

packetforge_ng_SOURCES = $(SRC_PF) $(LIBAIRCRACK_UTIL)
packetforge_ng_CFLAGS = $(COMMON_CFLAGS)
packetforge_ng_LDADD = $(COMMON_LDADD) $(LIBAC_LIBS) $(LIBAIRCRACK_UTIL_LIBS) $(CRYPTO_LIBS)

aireplay_ng_SOURCES = $(SRC_AR) $(LIBAIRCRACK_OSDEP) $(LIBAIRCRACK_UTIL)
aireplay_ng_CFLAGS = $(COMMON_CFLAGS) $(LIBNL_CFLAGS)
aireplay_ng_LDADD = $(COMMON_LDADD) $(LIBAIRCRACK_OSDEP_LIBS) $(LIBAC_LIBS) $(AIRPCAP_LIBS) $(LIBAIRCRACK_UTIL_LIBS) $(CRYPTO_LIBS)

airodump_ng_SOURCES = $(SRC_ADU) $(LIBAIRCRACK_OSDEP) $(LIBMCS) $(LIBAIRCRACK_UTIL)
airodump_ng_CFLAGS = $(COMMON_CFLAGS) $(PCRE_CFLAGS) $(LIBNL_CFLAGS)
airodump_ng_LDADD = $(COMMON_LDADD) $(PCRE_LIBS) $(LIBAIRCRACK_OSDEP_LIBS) $(LIBAC_LIBS) $(AIRPCAP_LIBS) $(LIBAIRCRACK_UTIL_LIBS) $(CRYPTO_LIBS)

airserv_ng_SOURCES = $(SRC_AS) $(LIBAIRCRACK_OSDEP) $(LIBAIRCRACK_UTIL)
airserv_ng_CFLAGS = $(COMMON_CFLAGS) $(LIBNL_CFLAGS)
airserv_ng_LDADD = $(COMMON_LDADD) $(LIBAIRCRACK_OSDEP_LIBS) $(LIBAC_LIBS) $(AIRPCAP_LIBS) $(LIBAIRCRACK_UTIL_LIBS) $(CRYPTO_LIBS)

airtun_ng_SOURCES = $(SRC_AT) $(LIBAIRCRACK_OSDEP) $(LIBAIRCRACK_UTIL)
airtun_ng_CFLAGS = $(COMMON_CFLAGS) $(LIBNL_CFLAGS)
airtun_ng_LDADD = $(COMMON_LDADD) $(LIBAIRCRACK_OSDEP_LIBS) $(LIBAC_LIBS) $(AIRPCAP_LIBS) $(LIBAIRCRACK_UTIL_LIBS) $(CRYPTO_LIBS)

ivstools_SOURCES = $(SRC_IV) $(LIBAIRCRACK_UTIL)
ivstools_CFLAGS = $(COMMON_CFLAGS)
ivstools_LDADD = $(COMMON_LDADD) $(LIBAC_LIBS) $(LIBAIRCRACK_UTIL_LIBS) $(CRYPTO_LIBS)

kstats_SOURCES = kstats.c
kstats_CFLAGS = $(LIBAC_CFLAGS) $(PTHREAD_CFLAGS)
kstats_LDADD = $(COMMON_LDADD) $(LIBAC_LIBS)

wesside_ng_SOURCES = $(SRC_WS) $(LIBAIRCRACK_OSDEP) $(LIBAIRCRACK_UTIL)
wesside_ng_CFLAGS = $(COMMON_CFLAGS) $(LIBNL_CFLAGS)
wesside_ng_LDADD = $(COMMON_LDADD) $(LIBAIRCRACK_OSDEP_LIBS) $(LIBAC_LIBS) $(LIBPTW_LIBS) $(AIRPCAP_LIBS) $(LIBAIRCRACK_UTIL_LIBS) $(CRYPTO_LIBS)

easside_ng_SOURCES = $(SRC_ES) $(LIBAIRCRACK_OSDEP) $(LIBAIRCRACK_UTIL)
easside_ng_CFLAGS = $(COMMON_CFLAGS) $(LIBNL_CFLAGS)
easside_ng_LDADD = $(COMMON_LDADD) $(LIBAIRCRACK_OSDEP_LIBS) $(LIBAC_LIBS) $(AIRPCAP_LIBS) $(LIBAIRCRACK_UTIL_LIBS) $(CRYPTO_LIBS)

buddy_ng_SOURCES = $(SRC_BUDDY) $(LIBAIRCRACK_UTIL)
buddy_ng_CFLAGS = $(LIBAC_CFLAGS) $(PTHREAD_CFLAGS)
buddy_ng_LDADD = $(COMMON_LDADD) $(LIBAC_LIBS) $(LIBAIRCRACK_UTIL_LIBS) $(CRYPTO_LIBS)

besside_ng_SOURCES = $(SRC_BS) $(LIBAIRCRACK_OSDEP) $(LIBAIRCRACK_UTIL)
besside_ng_CFLAGS = $(COMMON_CFLAGS) $(PCRE_CFLAGS) $(LIBNL_CFLAGS)
besside_ng_LDADD = $(COMMON_LDADD) $(PCRE_LIBS) $(LIBAIRCRACK_OSDEP_LIBS) $(LIBAC_LIBS) $(LIBPTW_LIBS) $(AIRPCAP_LIBS) $(LIBAIRCRACK_UTIL_LIBS) $(CRYPTO_LIBS)

besside_ng_crawler_SOURCES = $(SRC_BC)
besside_ng_crawler_CFLAGS = $(COMMON_CFLAGS) $(PCAP_CFLAGS)
besside_ng_crawler_LDADD = $(COMMON_LDADD) $(PCAP_LIBS) $(LIBAC_LIBS) $(CRYPTO_LIBS)

makeivs_ng_SOURCES = $(SRC_MI) $(LIBAIRCRACK_UTIL)
makeivs_ng_CFLAGS = $(COMMON_CFLAGS)
makeivs_ng_LDADD = $(COMMON_LDADD) $(LIBAC_LIBS) $(LIBAIRCRACK_UTIL_LIBS) $(CRYPTO_LIBS)

airolib_ng_SOURCES = $(SRC_AL) $(LIBCOW) $(LIBAIRCRACK_UTIL)
airolib_ng_CFLAGS = $(COMMON_CFLAGS) $(SQLITE3_CFLAGS) -DHAVE_REGEXP
airolib_ng_LDADD = $(COMMON_LDADD) $(SQLITE3_LDFLAGS) $(LIBAC_LIBS) $(LIBCOW_LIBS) $(LIBAIRCRACK_UTIL_LIBS) $(CRYPTO_LIBS)

airbase_ng_SOURCES = $(SRC_AB) $(LIBAIRCRACK_OSDEP) $(LIBAIRCRACK_UTIL)
airbase_ng_CFLAGS = $(COMMON_CFLAGS) $(LIBNL_CFLAGS)
airbase_ng_LDADD = $(COMMON_LDADD) $(LIBAIRCRACK_OSDEP_LIBS) $(LIBAC_LIBS) $(AIRPCAP_LIBS) $(LIBAIRCRACK_UTIL_LIBS) $(CRYPTO_LIBS)

airdecloak_ng_SOURCES = $(SRC_AU) $(LIBAIRCRACK_OSDEP) $(LIBAIRCRACK_UTIL)
airdecloak_ng_CFLAGS = $(COMMON_CFLAGS)
airdecloak_ng_LDADD = $(COMMON_LDADD) $(LIBAIRCRACK_OSDEP_LIBS) $(LIBAC_LIBS) $(AIRPCAP_LIBS) $(LIBAIRCRACK_UTIL_LIBS) $(CRYPTO_LIBS)

tkiptun_ng_SOURCES = $(SRC_TT) $(LIBAIRCRACK_OSDEP) $(LIBAIRCRACK_UTIL)
tkiptun_ng_CFLAGS = $(COMMON_CFLAGS) $(LIBNL_CFLAGS)
tkiptun_ng_LDADD = $(COMMON_LDADD) $(LIBAIRCRACK_OSDEP_LIBS) $(LIBAC_LIBS) $(AIRPCAP_LIBS) $(LIBAIRCRACK_UTIL_LIBS) $(CRYPTO_LIBS)

wpaclean_SOURCES = $(SRC_WC) $(LIBAIRCRACK_OSDEP)
wpaclean_CFLAGS = $(COMMON_CFLAGS) $(LIBNL_CFLAGS) $(LIBAIRCRACK_UTIL_CFLAGS)
wpaclean_LDADD = $(COMMON_LDADD) $(LIBAIRCRACK_OSDEP_LIBS) $(LIBAC_LIBS) $(AIRPCAP_LIBS) $(LIBAIRCRACK_UTIL_LIBS) $(CRYPTO_LIBS)

airventriloquist_ng_SOURCES = $(SRC_AV) $(LIBAIRCRACK_OSDEP) $(LIBAIRCRACK_UTIL)
airventriloquist_ng_CFLAGS = $(COMMON_CFLAGS) $(LIBNL_CFLAGS)
airventriloquist_ng_LDADD = $(COMMON_LDADD) $(LIBAIRCRACK_OSDEP_LIBS) $(LIBAC_LIBS) $(AIRPCAP_LIBS) $(LIBAIRCRACK_UTIL_LIBS) $(CRYPTO_LIBS)

libaclib_la_SOURCES = $(SRC_ACLIB)
libaclib_la_CFLAGS = $(COMMON_CFLAGS) $(LIBAIRCRACK_UTIL_CFLAGS)
libaclib_la_LIBADD = $(LIBAIRCRACK_UTIL_LIBS)
if !STATIC_CRYPTO
libaclib_la_LIBADD += $(LIBAIRCRACK_UTIL_LIBS)
endif

libcow_la_SOURCES = $(SRC_COW)
libcow_la_CFLAGS = $(COMMON_CFLAGS) $(LIBCOW_CFLAGS)
if !STATIC_CRYPTO
libcow_la_LIBADD = $(COMMON_LDADD)
endif

libptw_la_SOURCES = $(SRC_PTW)
libptw_la_CFLAGS = $(COMMON_CFLAGS)
if !STATIC_CRYPTO
libptw_la_LIBADD = $(COMMON_LDADD)
endif

noinst_LTLIBRARIES = libaclib.la libptw.la libcow.la

EXTRA_DIST = wpaclean.c \
             buddy-ng.c \
             aircrack-ng.h \
             version.h \
             airventriloquist-ng.h \
             airdecloak-ng.h \
             airserv-ng.c \
             besside-ng.c \
             wkp-frame.h \
             airolib-ng.c \
             aircrack-ptw-lib.h \
             makeivs-ng.c \
             easside-ng.c \
             crctable.h \
             airdecap-ng.c \
             airodump-ng.h \
             airbase-ng.c \
             besside-ng-crawler.c \
             tkiptun-ng.c \
             kstats.c \
             easside.h \
             aireplay-ng.c \
             ivstools.c \
             pcap.h \
             aircrack-ng.c \
             airodump-ng.c \
             crypto.c \
             airdecloak-ng.c \
             packetforge-ng.c \
             airventriloquist-ng.c \
             uniqueiv.c \
             gcrypt-openssl-wrapper.h \
             uniqueiv.h \
             wesside-ng.c \
             airtun-ng.c \
             linecount.h \
             aircrack-ptw-lib.c \
             crypto.h \
             sha1-git.c \
             sha1-git.h \
             cowpatty.c \
             cowpatty.h \
             session.c \
             session.h


@CODE_COVERAGE_RULES@
