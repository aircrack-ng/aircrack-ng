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

SRC_COW			= %D%/cowpatty/cowpatty.c
SRC_PTW			= %D%/ptw/aircrack-ptw-lib.c

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

noinst_LTLIBRARIES += libcowpatty.la libptw.la

EXTRA_DIST +=	%D%/cowpatty/cowpatty.c

include %D%/radiotap/Makefile.inc
include %D%/osdep/Makefile.inc
