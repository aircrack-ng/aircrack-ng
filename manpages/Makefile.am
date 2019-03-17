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

dist_man1_MANS = aircrack-ng.1 \
                 airdecap-ng.1 \
                 packetforge-ng.1 \
                 ivstools.1 \
                 kstats.1 \
                 makeivs-ng.1 \
                 airdecloak-ng.1

dist_man8_MANS = airodump-ng-oui-update.8

if LINUX
dist_man8_MANS += airmon-ng.8
endif

if FREEBSD
dist_man8_MANS += airmon-ng.8
endif

if HAVE_AIRPCAP_OR_PCAP

if HAVE_PCAP
dist_man1_MANS += besside-ng-crawler.1
endif

dist_man1_MANS += wpaclean.1

dist_man8_MANS += airbase-ng.8 \
                  aireplay-ng.8 \
                  airodump-ng.8 \
                  airserv-ng.8 \
                  airtun-ng.8
endif

if HAVE_SQLITE3
dist_man1_MANS += airolib-ng.1
endif

if EXPERIMENTAL
dist_man1_MANS += buddy-ng.1

if HAVE_AIRPCAP_OR_PCAP
dist_man8_MANS += airventriloquist-ng.8 \
                  besside-ng.8 \
                  easside-ng.8 \
                  tkiptun-ng.8 \
                  wesside-ng.8
endif
endif

EXTRA_DIST = airmon-ng.8.in \
             airolib-ng.1.in \
             besside-ng-crawler.1.in \
             buddy-ng.1.in \
             airventriloquist-ng.8.in \
             besside-ng.8.in \
             easside-ng.8.in \
             tkiptun-ng.8.in \
             wesside-ng.8.in \
             wpaclean.1.in \
             airbase-ng.8.in \
             aireplay-ng.8.in \
             airodump-ng.8.in \
             airserv-ng.8.in \
             airtun-ng.8.in
