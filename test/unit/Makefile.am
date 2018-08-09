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

AM_CPPFLAGS = -I$(top_srcdir) \
              -I$(top_srcdir)/src/include \
              -I$(top_srcdir)/src \
              $(CRYPTO_INCLUDES)

AM_TESTS_ENVIRONMENT= \
	TEST_SRCDIR="$(abs_srcdir)" 		\
	TEST_BUILDDIR="$(abs_builddir)" 	\
	CMOCKA_MESSAGE_OUTPUT=TAP

LIBAIRCRACK_CRYPTO_PATH = $(abs_top_builddir)/src/aircrack-crypto/

LIBAC	= ../../src/libaclib.la
LIBAC_LIBS = -L../../src -laclib

LIBAIRCRACK_CRYPTO = ../../src/aircrack-crypto/libaircrack-crypto.la
LIBAIRCRACK_CRYPTO_LIBS = -L../../src/aircrack-crypto -laircrack-crypto

LIBAIRCRACK_UTIL	= ../../src/aircrack-util/libaircrack-util.la
LIBAIRCRACK_UTIL_LIBS = -L../../src/aircrack-util -laircrack-util

COMMON_CFLAGS = $(PTHREAD_CFLAGS) \
				$(CRYPTO_CFLAGS) \
				$(ZLIB_CFLAGS) \
				$(CMOCKA_CFLAGS)
COMMON_LDADD  = $(PTHREAD_LIBS) \
			    $(CRYPTO_LIBS) \
			    $(ZLIB_LIBS) \
			    $(CMOCKA_LIBS)

test_calc_one_pmk_SOURCES = test-calc-one-pmk.c \
							$(LIBAIRCRACK_CRYPTO)
test_calc_one_pmk_CFLAGS  = $(COMMON_CFLAGS)
test_calc_one_pmk_LDFLAGS = -rdynamic
test_calc_one_pmk_LDADD   = $(LIBAIRCRACK_CRYPTO_LIBS) \
						    $(COMMON_LDADD)

test_string_has_suffix_SOURCES = test-string-has-suffix.c \
								 $(LIBAIRCRACK_UTIL)
test_string_has_suffix_CFLAGS  = $(COMMON_CFLAGS)
test_string_has_suffix_LDFLAGS = -rdynamic
test_string_has_suffix_LDADD   = $(LIBAIRCRACK_UTIL_LIBS) $(COMMON_LDADD)

test_wpapsk_SOURCES = test-wpapsk.c \
					  $(LIBAIRCRACK_UTIL)
test_wpapsk_CFLAGS  = "-DLIBAIRCRACK_CRYPTO_PATH=\"$(LIBAIRCRACK_CRYPTO_PATH)\"" \
					  "-DABS_TOP_SRCDIR=\"$(abs_top_srcdir)\"" \
					  "-DABS_TOP_BUILDDIR=\"$(abs_top_builddir)\"" \
					  "-DLIBDIR=\"$(libdir)\"" \
					  $(COMMON_CFLAGS)
test_wpapsk_LDFLAGS = -rdynamic
test_wpapsk_LDADD   = $(LIBAIRCRACK_CRYPTO_LIBS) \
					  $(LIBAIRCRACK_UTIL_LIBS) \
					  $(COMMON_LDADD)

test_wpapsk_cmac_SOURCES = test-wpapsk-cmac.c \
						   $(LIBAIRCRACK_UTIL)
test_wpapsk_cmac_CFLAGS = "-DLIBAIRCRACK_CRYPTO_PATH=\"$(LIBAIRCRACK_CRYPTO_PATH)\"" \
						  "-DABS_TOP_SRCDIR=\"$(abs_top_srcdir)\"" \
						  "-DABS_TOP_BUILDDIR=\"$(abs_top_builddir)\"" \
						  "-DLIBDIR=\"$(libdir)\"" \
						  $(COMMON_CFLAGS)
test_wpapsk_cmac_LDFLAGS = -rdynamic
test_wpapsk_cmac_LDADD   = $(LIBAIRCRACK_UTIL_LIBS) \
						   $(COMMON_LDADD)

TESTS = test-calc-one-pmk test-string-has-suffix

if !STATIC_BUILD
TESTS += test-wpapsk
TESTS += test-wpapsk-cmac
endif

check_PROGRAMS = test-calc-one-pmk test-string-has-suffix

if !STATIC_BUILD
check_PROGRAMS += test-wpapsk
check_PROGRAMS += test-wpapsk-cmac
endif


@CODE_COVERAGE_RULES@

@VALGRIND_CHECK_RULES@
