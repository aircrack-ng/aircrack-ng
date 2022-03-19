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

AM_TESTS_ENVIRONMENT = \
	. $(builddir)/test/test-env.sh; \
    TEST_SRCDIR="$(abs_srcdir)"; export TEST_SRCDIR; \
    TEST_BUILDDIR="$(abs_builddir)"; export TEST_BUILDDIR; \
    CMOCKA_MESSAGE_OUTPUT=TAP; export CMOCKA_MESSAGE_OUTPUT; \
	if test -d /usr/xpg4/bin; then \
	  PATH=/usr/xpg4/bin:$$PATH; export PATH; \
	fi;

TESTS_ENVIRONMENT ?= $(AM_TESTS_ENVIRONMENT)

test_hex_string_to_array_SOURCES = %D%/test-hex_string_to_array.c
test_hex_string_to_array_LDADD = $(libaccrypto_la_LIBADD) $(libaircrack_la_LIBADD) $(LIBACCRYPTO_LIBS) $(LIBAIRCRACK_LIBS)

check_PROGRAMS += test-hex_string_to_array

TESTS += %D%/test-hex_string_to_array.sh \
		 %D%/test-aircrack-ng-0001.sh \
		 %D%/test-aircrack-ng-0002.sh \
		 %D%/test-aircrack-ng-0003.sh \
		 %D%/test-aircrack-ng-0004.sh \
		 %D%/test-aircrack-ng-0005.sh \
		 %D%/test-aircrack-ng-0006.sh \
		 %D%/test-aircrack-ng-0007.sh \
		 %D%/test-aircrack-ng-0008.sh \
		 %D%/test-aircrack-ng-0009.sh \
		 %D%/test-aircrack-ng-0010.sh \
		 %D%/test-aircrack-ng-0011.sh \
		 %D%/test-aircrack-ng-0012.sh \
		 %D%/test-aircrack-ng-0013.sh \
		 %D%/test-aircrack-ng-0014.sh \
		 %D%/test-aircrack-ng-0015.sh \
		 %D%/test-aircrack-ng-0016.sh \
		 %D%/test-aircrack-ng-0017.sh \
		 %D%/test-aircrack-ng-0018.sh \
		 %D%/test-aircrack-ng-0019.sh \
		 %D%/test-aircrack-ng-0021.sh \
		 %D%/test-aircrack-ng-0022.sh \
		 %D%/test-aircrack-ng-0023.sh \
		 %D%/test-airdecap-ng-0001.sh \
		 %D%/test-airdecap-ng-0002.sh \
		 %D%/test-airdecap-ng-0003.sh \
		 %D%/test-airdecap-ng-0004.sh \
		 %D%/test-airdecap-ng-0005.sh \
		 %D%/test-airdecap-ng-0006.sh \
		 %D%/test-wpaclean-0001.sh \
		 %D%/test-wpaclean-0002.sh \
		 %D%/test-alltools.sh

if EXPECT
TESTS += %D%/test-aircrack-ng-0020.sh
endif

if LINUX
INTEGRATION_TESTS += %D%/test-aireplay-ng-0001.sh \
		 %D%/test-aireplay-ng-0002.sh \
		 %D%/test-aireplay-ng-0003.sh \
		 %D%/test-aireplay-ng-0004.sh \
		 %D%/test-aireplay-ng-0005.sh \
		 %D%/test-aireplay-ng-0006.sh \
		 %D%/test-aireplay-ng-0007.sh \
         %D%/test-aireplay-ng-0008.sh \
		 %D%/test-airbase-ng-0001.sh \
		 %D%/test-airbase-ng-0002.sh \
		 %D%/test-airbase-ng-0003.sh \
		 %D%/test-airodump-ng-0001.sh \
		 %D%/test-airodump-ng-0002.sh \
		 %D%/test-airodump-ng-0003.sh \
		 %D%/test-airodump-ng-0004.sh \
		 %D%/test-airodump-ng-0005.sh \
		 %D%/test-airodump-ng-0006.sh
endif

if HAVE_SQLITE3
TESTS += %D%/test-airolib-ng-0001.sh
endif

EXTRA_DIST += %D%/test-hex_string_to_array.sh \
			  %D%/test-aircrack-ng-0001.sh \
			  %D%/test-aircrack-ng-0002.sh \
			  %D%/test-aircrack-ng-0003.sh \
			  %D%/test-aircrack-ng-0004.sh \
			  %D%/test-aircrack-ng-0005.sh \
			  %D%/test-aircrack-ng-0006.sh \
			  %D%/test-aircrack-ng-0007.sh \
			  %D%/test-aircrack-ng-0008.sh \
			  %D%/test-aircrack-ng-0009.sh \
			  %D%/test-aircrack-ng-0010.sh \
			  %D%/test-aircrack-ng-0011.sh \
			  %D%/test-aircrack-ng-0012.sh \
			  %D%/test-aircrack-ng-0013.sh \
			  %D%/test-aircrack-ng-0014.sh \
			  %D%/test-aircrack-ng-0015.sh \
			  %D%/test-aircrack-ng-0016.sh \
			  %D%/test-aircrack-ng-0017.sh \
			  %D%/test-aircrack-ng-0018.sh \
			  %D%/test-aircrack-ng-0019.sh \
			  %D%/test-aircrack-ng-0021.sh \
			  %D%/test-aircrack-ng-0022.sh \
			  %D%/test-aircrack-ng-0023.sh \
			  %D%/test-airdecap-ng-0001.sh \
			  %D%/test-airdecap-ng-0002.sh \
			  %D%/test-airdecap-ng-0003.sh \
			  %D%/test-airdecap-ng-0004.sh \
			  %D%/test-airdecap-ng-0005.sh \
			  %D%/test-airdecap-ng-0006.sh \
			  %D%/test-wpaclean-0001.sh \
			  %D%/test-wpaclean-0002.sh \
			  %D%/test-alltools.sh \
			  %D%/wpaclean_crash.pcap \
              %D%/int-test-common.sh \
              %D%/wep.open.system.authentication.cap \
              %D%/wpa2-psk-linksys.cap \
              %D%/wpa3-psk.pcap \
              %D%/test-hex_string_to_array.c \
              %D%/wpa.cap \
              %D%/test.ivs \
              %D%/StayAlfred.hccapx \
              %D%/test1.pcap \
              %D%/test-pmkid.pcap \
              %D%/capture_wds-01.cap \
              %D%/wpa-psk-linksys.cap \
              %D%/wpa2.eapol.cap \
              %D%/wps2.0.pcap \
              %D%/verify_inject.py \
              %D%/replay.py \
              %D%/password.lst \
              %D%/password-2.lst \
              %D%/password-3.lst \
              %D%/n-02.cap \
	      %D%/zn2i.pcap \
              %D%/wep.shared.key.authentication.cap \
              %D%/wep_64_ptw.cap \
              %D%/pingreply.c \
              %D%/Chinese-SSID-Name.pcap \
              %D%/passphrases.db \
			  %D%/test-airdecap-ng.sh \
			  %D%/test-airolib-sqlite.sh \
			  %D%/MOM1.cap \
			  %D%/pass.txt \
			  %D%/test23.pcap \
			  %D%/testm1m2m3.pcap

if EXPECT
EXTRA_DIST += %D%/test-aircrack-ng-0020.sh \
              %D%/wep_64_ptw_01.cap \
              %D%/wep_64_ptw_02.cap \
              %D%/wep_64_ptw_03.cap \
              %D%/wep_64_ptw_04.cap
endif

if LINUX
EXTRA_DIST += %D%/test-aireplay-ng-0001.sh \
			  %D%/test-aireplay-ng-0002.sh \
			  %D%/test-aireplay-ng-0003.sh \
			  %D%/test-aireplay-ng-0004.sh \
			  %D%/test-aireplay-ng-0005.sh \
			  %D%/test-aireplay-ng-0006.sh \
			  %D%/test-aireplay-ng-0007.sh \
              %D%/test-aireplay-ng-0007.sh \
			  %D%/test-airbase-ng-0001.sh \
			  %D%/test-airbase-ng-0002.sh \
			  %D%/test-airbase-ng-0003.sh \
			  %D%/test-airodump-ng-0001.sh \
			  %D%/test-airodump-ng-0002.sh \
			  %D%/test-airodump-ng-0003.sh \
			  %D%/test-airodump-ng-0004.sh \
			  %D%/test-airodump-ng-0005.sh\
			  %D%/test-airodump-ng-0006.sh
endif

if HAVE_SQLITE3
EXTRA_DIST += %D%/test-airolib-ng-0001.sh
endif

if CMOCKA
include %D%/unit/Makefile.inc
endif
include %D%/cryptounittest/Makefile.inc
