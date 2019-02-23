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

ACLOCAL_AMFLAGS = -I build/m4/stubs -I build/m4

SUBDIRS = manpages \
		  scripts

AM_CPPFLAGS = -I$(top_srcdir) \
			  -I$(top_srcdir)/src \
			  -I$(top_srcdir)/src/include \
			  -I$(top_srcdir)/src/aircrack-util \
			  -I$(top_srcdir)/src/aircrack-crypto \
			  $(CRYPTO_INCLUDES) \
			  $(CODE_COVERAGE_CPPFLAGS)

CFLAGS		+= $(CODE_COVERAGE_CFLAGS)
CXXFLAGS	+=	$(CODE_COVERAGE_CXXFLAGS)
LIBS		+=	$(CODE_COVERAGE_LIBS)

bin_PROGRAMS =
sbin_PROGRAMS =
noinst_LTLIBRARIES =
lib_LTLIBRARIES =
EXTRA_DIST =
check_PROGRAMS =
TESTS =

LIBAC_LIBS = libaclib.la
LIBPTW_LIBS = libptw.la
LIBLINECOUNT_LIBS = liblinecount.la
LIBCOW_LIBS= libcow.la
LIBAIRCRACK_CRYPTO_LIBS = libaircrack-crypto.la

LIBAIRCRACK_CRYPTO_X86_AVX2_LIBS = libaircrack-crypto-x86-avx2.la

LIBAIRCRACK_CRYPTO_X86_AVX_LIBS = libaircrack-crypto-x86-avx.la

LIBAIRCRACK_CRYPTO_X86_SSE2_LIBS = libaircrack-crypto-x86-sse2.la

LIBAIRCRACK_UTIL_LIBS = libaircrack-util.la

LIBAIRCRACK_OSDEP_LIBS= libaircrack-osdep.la
if CYGWIN
LIBAIRCRACK_OSDEP_LIBS+= -liphlpapi -lsetupapi -luuid
endif

LIBRADIOTAP_LIBS = libradiotap.la

LIBAIRCRACK_CRYPTO_PATH = $(abs_top_builddir)/

include $(top_srcdir)/src/Makefile.inc
include $(top_srcdir)/test/Makefile.inc

include $(top_srcdir)/aminclude_static.am

clean-local: code-coverage-clean
distclean-local: code-coverage-dist-clean
