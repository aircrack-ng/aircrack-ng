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

SUBDIRS = cryptounittest

AM_CPPFLAGS = -I$(top_srcdir) \
              -I$(top_srcdir)/src/include \
              -I$(top_srcdir)/src \
              $(CRYPTO_INCLUDES)

AM_TESTS_ENVIRONMENT = \
	. $(builddir)/test-env.sh; \
	if test -d /usr/xpg4/bin; then \
	  PATH=/usr/xpg4/bin:$$PATH; export PATH; \
	fi;

TESTS_ENVIRONMENT ?= $(AM_TESTS_ENVIRONMENT)

LIBAC	= ../src/libaclib.la
LIBAC_LIBS = -L../src -laclib

test_hex_string_to_array_SOURCES = test-hex_string_to_array.c
test_hex_string_to_array_LDADD = $(LIBAC_LIBS)

check_PROGRAMS = test-hex_string_to_array

TESTS = test-hex_string_to_array.sh \
		test-aircrack-ng-0001.sh \
		test-aircrack-ng-0002.sh \
		test-aircrack-ng-0003.sh \
		test-aircrack-ng-0004.sh \
		test-aircrack-ng-0005.sh \
		test-airdecap-ng-0001.sh \
		test-airdecap-ng-0002.sh \
		test-airdecap-ng-0003.sh \
		test-airdecap-ng-0004.sh

if HAVE_SQLITE3
TESTS += test-airolib-ng-0001.sh
endif

EXTRA_DIST = test-hex_string_to_array.sh \
			 test-aircrack-ng-0001.sh \
			 test-aircrack-ng-0002.sh \
			 test-aircrack-ng-0003.sh \
			 test-aircrack-ng-0004.sh \
			 test-aircrack-ng-0005.sh \
			 test-airdecap-ng-0001.sh \
			 test-airdecap-ng-0002.sh \
			 test-airdecap-ng-0003.sh \
			 test-airdecap-ng-0004.sh \
             wep.open.system.authentication.cap \
             wpa2-psk-linksys.cap \
             test-hex_string_to_array.c \
             wpa.cap \
             wpa-psk-linksys.cap \
             wpa2.eapol.cap \
             wps2.0.pcap \
             verify_inject.py \
             replay.py \
             password.lst \
             wep.shared.key.authentication.cap \
             wep_64_ptw.cap \
             pingreply.c \
             Chinese-SSID-Name.pcap \
             passphrases.db \
			 test-airdecap-ng.sh \
			 test-airolib-sqlite.sh

if HAVE_SQLITE3
EXTRA_DIST += test-airolib-ng-0001.sh
endif


@CODE_COVERAGE_RULES@

@VALGRIND_CHECK_RULES@
