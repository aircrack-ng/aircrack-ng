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

aircrack_ngheadersdir = $(includedir)/aircrack-ng
aircrack_ngheaders_HEADERS = 	%D%/aircrack-ng/adt/avl_tree.h \
															%D%/aircrack-ng/adt/circular_buffer.h \
															%D%/aircrack-ng/adt/circular_queue.h \
															%D%/aircrack-ng/aircrack-ng.h \
															%D%/aircrack-ng/ce-wep/uniqueiv.h \
															%D%/aircrack-ng/cowpatty/cowpatty.h \
															%D%/aircrack-ng/cpu/cpuset.h \
															%D%/aircrack-ng/cpu/simd_cpuid.h \
															%D%/aircrack-ng/cpu/trampoline.h \
															%D%/aircrack-ng/crypto/crctable.h \
															%D%/aircrack-ng/crypto/crypto.h \
															%D%/aircrack-ng/crypto/gcrypt-openssl-wrapper.h \
															%D%/aircrack-ng/crypto/sha1-git.h \
															%D%/aircrack-ng/crypto/sha1-sse2.h \
															%D%/aircrack-ng/defs.h \
															%D%/aircrack-ng/osdep/byteorder.h \
															%D%/aircrack-ng/osdep/channel.h \
															%D%/aircrack-ng/osdep/common.h \
															%D%/aircrack-ng/osdep/network.h \
															%D%/aircrack-ng/osdep/osdep.h \
															%D%/aircrack-ng/osdep/packed.h \
															%D%/aircrack-ng/ptw/aircrack-ptw-lib.h \
															%D%/aircrack-ng/support/common.h \
															%D%/aircrack-ng/support/communications.h \
															%D%/aircrack-ng/support/crypto_engine_loader.h \
															%D%/aircrack-ng/support/fragments.h \
															%D%/aircrack-ng/support/mcs_index_rates.h \
															%D%/aircrack-ng/support/pcap_local.h \
															%D%/aircrack-ng/support/station.h \
															%D%/aircrack-ng/tui/console.h \
															%D%/aircrack-ng/utf8/verifyssid.h \
															%D%/aircrack-ng/version.h

EXTRA_DIST += $(aircrack_ngheaders_HEADERS)
