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

AM_CPPFLAGS = -I$(top_srcdir) \
              -I$(top_srcdir)/src/include \
              -I$(top_srcdir)/src \
              $(CRYPTO_INCLUDES)

LIBAC	= ../../src/libaclib.la
LIBAC_LIBS = -L../../src -laclib


SRCS_TEST_EWEP  = test-encrypt-wep.c
SRCS_TEST_CPMK  = test-calc-pmk.c
SRCS_TEST_4PMK  = test-calc-4pmk.c
SRCS_TEST_CMIC  = test-calc-mic.c
SRCS_TEST_CPTK  = test-calc-ptk.c
SRCS_TEST_DCMP  = test-decrypt-ccmp.c
SRCS_TEST_ECMP  = test-encrypt-ccmp.c

test_encrypt_wep_SOURCES = $(SRCS_TEST_EWEP)
test_encrypt_wep_CFLAGS = $(AM_CPPFLAGS) $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS)
test_encrypt_wep_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBAC_LIBS)

test_calc_pmk_SOURCES = $(SRCS_TEST_CPMK)
test_calc_pmk_CFLAGS = $(AM_CPPFLAGS) $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS)
test_calc_pmk_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBAC_LIBS)

test_calc_4pmk_SOURCES = $(SRCS_TEST_4PMK)
test_calc_4pmk_CFLAGS = -DOLD_SSE_CORE=1 $(AM_CPPFLAGS) $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS)
test_calc_4pmk_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBAC_LIBS)

test_calc_mic_SOURCES = $(SRCS_TEST_CMIC)
test_calc_mic_CFLAGS = $(AM_CPPFLAGS) $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS)
test_calc_mic_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBAC_LIBS)

test_calc_ptk_SOURCES = $(SRCS_TEST_CPTK)
test_calc_ptk_CFLAGS = $(AM_CPPFLAGS) $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS)
test_calc_ptk_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBAC_LIBS)

test_encrypt_ccmp_SOURCES = $(SRCS_TEST_ECMP)
test_encrypt_ccmp_CFLAGS = $(AM_CPPFLAGS) $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS)
test_encrypt_ccmp_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBAC_LIBS)

test_decrypt_ccmp_SOURCES = $(SRCS_TEST_DCMP)
test_decrypt_ccmp_CFLAGS = $(AM_CPPFLAGS) $(PTHREAD_CFLAGS) $(CRYPTO_CFLAGS)
test_decrypt_ccmp_LDADD = $(PTHREAD_LIBS) $(CRYPTO_LIBS) $(LIBAC_LIBS)


TESTS           = test-encrypt-wep \
                  test-calc-pmk \
                  test-calc-mic \
                  test-calc-ptk \
                  test-encrypt-ccmp \
                  test-decrypt-ccmp \
                  test-calc-4pmk

check_PROGRAMS	= test-encrypt-wep \
                  test-calc-pmk \
                  test-calc-mic \
                  test-calc-ptk \
                  test-encrypt-ccmp \
                  test-decrypt-ccmp \
                  test-calc-4pmk

EXTRA_DIST = tests.h


@CODE_COVERAGE_RULES@

@VALGRIND_CHECK_RULES@
