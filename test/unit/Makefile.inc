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

UNIT_COMMON_CFLAGS =	$(PTHREAD_CFLAGS) \
											$(CRYPTO_CFLAGS) \
											$(ZLIB_CFLAGS) \
											$(CMOCKA_CFLAGS)

UNIT_COMMON_LDADD  =	$(PTHREAD_LIBS) \
											$(CRYPTO_LDFLAGS) \
											$(CRYPTO_LIBS) \
											$(ZLIB_LIBS) \
											$(LIBAIRCRACK_LIBS) \
											$(CMOCKA_LIBS)

test_calc_one_pmk_SOURCES = %D%/test-calc-one-pmk.c
test_calc_one_pmk_CFLAGS  = $(UNIT_COMMON_CFLAGS)
test_calc_one_pmk_LDFLAGS = -rdynamic
test_calc_one_pmk_LDADD   = $(LIBAIRCRACK_CE_WPA_LIBS) \
														$(UNIT_COMMON_LDADD)

test_circular_buffer_SOURCES = %D%/test-circular-buffer.c
test_circular_buffer_CFLAGS  = $(UNIT_COMMON_CFLAGS)
test_circular_buffer_LDFLAGS = -rdynamic
test_circular_buffer_LDADD   = $(LIBAIRCRACK_LIBS) $(UNIT_COMMON_LDADD)

test_circular_queue_SOURCES = %D%/test-circular-queue.c
test_circular_queue_CFLAGS  = $(UNIT_COMMON_CFLAGS)
test_circular_queue_LDFLAGS = -rdynamic
test_circular_queue_LDADD   = $(LIBAIRCRACK_LIBS) $(UNIT_COMMON_LDADD)

test_string_has_suffix_SOURCES = %D%/test-string-has-suffix.c
test_string_has_suffix_CFLAGS  = $(UNIT_COMMON_CFLAGS)
test_string_has_suffix_LDFLAGS = -rdynamic
test_string_has_suffix_LDADD   = $(LIBAIRCRACK_LIBS) $(UNIT_COMMON_LDADD)

test_wpapsk_SOURCES = %D%/test-wpapsk.c
test_wpapsk_CFLAGS  = "-DLIBAIRCRACK_CE_WPA_PATH=\"$(LIBAIRCRACK_CE_WPA_PATH)\"" \
											"-DABS_TOP_SRCDIR=\"$(abs_top_srcdir)\"" \
											"-DABS_TOP_BUILDDIR=\"$(abs_top_builddir)\"" \
											"-DLIBDIR=\"$(libdir)\"" \
											$(UNIT_COMMON_CFLAGS)
test_wpapsk_LDFLAGS = -rdynamic
test_wpapsk_LDADD   = $(LIBAIRCRACK_CE_WPA_LIBS) \
											$(LIBAIRCRACK_LIBS) \
											$(UNIT_COMMON_LDADD)

test_wpapsk_cmac_SOURCES = %D%/test-wpapsk-cmac.c
test_wpapsk_cmac_CFLAGS  =	"-DLIBAIRCRACK_CE_WPA_PATH=\"$(LIBAIRCRACK_CE_WPA_PATH)\"" \
														"-DABS_TOP_SRCDIR=\"$(abs_top_srcdir)\"" \
														"-DABS_TOP_BUILDDIR=\"$(abs_top_builddir)\"" \
														"-DLIBDIR=\"$(libdir)\"" \
														$(UNIT_COMMON_CFLAGS)
test_wpapsk_cmac_LDFLAGS = -rdynamic
test_wpapsk_cmac_LDADD   = $(LIBAIRCRACK_LIBS) \
												   $(UNIT_COMMON_LDADD)

TESTS += test-calc-one-pmk test-circular-buffer test-circular-queue test-string-has-suffix

if !STATIC_BUILD
TESTS += test-wpapsk
TESTS += test-wpapsk-cmac
endif

check_PROGRAMS += test-calc-one-pmk test-circular-buffer test-circular-queue test-string-has-suffix

if !STATIC_BUILD
check_PROGRAMS += test-wpapsk
check_PROGRAMS += test-wpapsk-cmac
endif
