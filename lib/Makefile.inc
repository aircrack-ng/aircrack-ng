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

SRC_CE_WEP	=	%D%/ce-wep/uniqueiv.c
SRC_COW			= %D%/cowpatty/cowpatty.c
SRC_CRYPTO	=	%D%/crypto/crypto.c
SRC_PTW			= %D%/ptw/aircrack-ptw-lib.c
SRC_LIBAC		= %D%/libac/adt/avl_tree.c \
							%D%/libac/adt/circular_buffer.c \
							%D%/libac/adt/circular_queue.c \
							%D%/libac/cpu/simd_cpuid.c \
							%D%/libac/cpu/trampoline.c \
							%D%/libac/support/fragments.c \
							%D%/libac/support/common.c \
							%D%/libac/support/communications.c \
							%D%/libac/support/crypto_engine_loader.c \
							%D%/libac/support/mcs_index_rates.c \
							%D%/libac/tui/console.c \
							%D%/libac/utf8/verifyssid.c

if LIBGCRYPT
SRC_CRYPTO	+=	%D%/crypto/sha1-git.c
endif

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

libaircrack_la_SOURCES	= $(SRC_LIBAC) $(TRAMPOLINE) $(CPUSET)
libaircrack_la_CFLAGS		= $(COMMON_CFLAGS) $(PCRE_CFLAGS) \
													"-DLIBAIRCRACK_CRYPTO_PATH=\"$(LIBAIRCRACK_CRYPTO_PATH)\"" \
													"-DABS_TOP_SRCDIR=\"$(abs_top_srcdir)\"" \
													"-DABS_TOP_BUILDDIR=\"$(abs_top_builddir)\"" \
													"-DLIBDIR=\"$(libdir)\""
libaircrack_la_LIBADD		= $(COMMON_LDADD) $(LIBAIRCRACK_OSDEP_LIBS) $(PCRE_LIBS) $(CRYPTO_LIBS)

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

libaccrypto_la_SOURCES	= $(SRC_CRYPTO)
libaccrypto_la_CFLAGS		= $(COMMON_CFLAGS) $(PCRE_CFLAGS)
libaccrypto_la_LIBADD		= $(PCRE_LIBS) $(LIBAIRCRACK_OSDEP_LIBS) $(CRYPTO_LIBS)

libaircrack_ce_wep_la_SOURCES	= $(SRC_CE_WEP)
libaircrack_ce_wep_la_CFLAGS	= $(COMMON_CFLAGS)
libaircrack_ce_wep_la_LIBADD	= $(CRYPTO_LIBS)

noinst_LTLIBRARIES += libaircrack-ce-wep.la libcowpatty.la libaccrypto.la libptw.la libaircrack.la

EXTRA_DIST +=	%D%/ce-wep/uniqueiv.c \
							%D%/cowpatty/cowpatty.c \
							%D%/crypto/crypto.c \
							%D%/ptw/aircrack-ptw-lib.c \
							%D%/lib/libac/adt/avl_tree.c \
							%D%/lib/libac/adt/circular_buffer.c \
							%D%/lib/libac/adt/circular_queue.c \
							%D%/lib/libac/cpu/simd_cpuid.c \
							%D%/lib/libac/cpu/cpuset_hwloc.c \
							%D%/lib/libac/cpu/trampoline.c \
							%D%/lib/libac/cpu/trampoline_x86.c \
							%D%/lib/libac/cpu/trampoline_stubs.c \
							%D%/lib/libac/cpu/trampoline_arm.c \
							%D%/lib/libac/cpu/cpuset_pthread.c \
							%D%/lib/libac/cpu/trampoline_ppc.c \
							%D%/lib/libac/tui/console.c \
							%D%/lib/libac/utf8/verifyssid.c \
							%D%/lib/libac/support/common.c \
							%D%/lib/libac/support/communications.c \
							%D%/lib/libac/support/mcs_index_rates.c \
							%D%/lib/libac/support/fragments.c \
							%D%/lib/libac/support/crypto_engine_loader.c \
							%D%/lib/osdep/openbsd.c \
							%D%/lib/osdep/darwin.c \
							%D%/lib/osdep/crctable_osdep.h \
							%D%/lib/osdep/common.c \
							%D%/lib/osdep/darwin_tap.c \
							%D%/lib/osdep/cygwin.c \
							%D%/lib/osdep/aircrack_ng_airpcap.h \
							%D%/lib/osdep/linux.c \
							%D%/lib/osdep/file.c \
							%D%/lib/osdep/linux_tap.c \
							%D%/lib/osdep/tap-win32/common.h \
							%D%/lib/osdep/airpcap.c \
							%D%/lib/osdep/cygwin.h \
							%D%/lib/osdep/netbsd.c \
							%D%/lib/osdep/freebsd_tap.c \
							%D%/lib/osdep/freebsd.c \
							%D%/lib/osdep/osdep.c \
							%D%/lib/osdep/dummy_tap.c \
							%D%/lib/osdep/openbsd_tap.c \
							%D%/lib/osdep/dummy.c \
							%D%/lib/osdep/netbsd_tap.c \
							%D%/lib/osdep/network.c \
							%D%/lib/osdep/cygwin_tap.c \
							%D%/lib/radiotap/parse.c \
							%D%/lib/radiotap/radiotap_iter.h \
							%D%/lib/radiotap/radiotap.h \
							%D%/lib/radiotap/radiotap.c \
							%D%/lib/radiotap/platform.h

include %D%/radiotap/Makefile.inc
include %D%/osdep/Makefile.inc
