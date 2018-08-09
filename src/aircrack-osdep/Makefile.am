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

SUBDIRS = radiotap

AM_CPPFLAGS = -I$(top_srcdir) \
              -I$(top_srcdir)/src/include \
              -I$(top_srcdir)/src \
              $(LIBNL_CFLAGS)

SRCS_COMMON = network.c file.c
SRCS = osdep.c $(SRCS_COMMON)

SRCS_APCAP = airpcap.c

SRCS_OBSD = $(SRCS) openbsd.c openbsd_tap.c common.c
SRCS_NBSD	= $(SRCS) netbsd.c netbsd_tap.c common.c
SRCS_FBSD	= $(SRCS) freebsd.c freebsd_tap.c common.c
SRCS_LINUX	= $(SRCS) linux.c linux_tap.c common.c
SRCS_DUMMY	= $(SRCS) dummy.c dummy_tap.c common.c
SRCS_CYGWIN	= $(SRCS) cygwin.c cygwin_tap.c common.c
SRCS_DARWIN = $(SRCS) darwin.c darwin_tap.c common.c

LIBRADIOTAP_LIBS = radiotap/libradiotap.la

if AIRPCAP
SRCS_CYGWIN    += $(SRCS_APCAP)
endif

if CYGWIN
if AIRPCAP
libaircrack_osdep_la_SOURCES = $(SRCS_CYGWIN)
libaircrack_osdep_la_CFLAGS = $(AM_CPPFLAGS) $(AIRPCAP_CFLAGS)
libaircrack_osdep_la_LIBADD = $(AIRPCAP_LIBS) $(LIBRADIOTAP_LIBS) -lsetupapi -liphlpapi
else
libaircrack_osdep_la_SOURCES = $(SRCS_CYGWIN)
endif
endif

if DARWIN
libaircrack_osdep_la_SOURCES = $(SRCS_DARWIN)
endif

if DUMMY
libaircrack_osdep_la_SOURCES = $(SRCS_DUMMY)
endif

if FREEBSD
libaircrack_osdep_la_SOURCES = $(SRCS_FBSD)
endif

if LINUX
libaircrack_osdep_la_SOURCES = $(SRCS_LINUX)
libaircrack_osdep_la_LIBADD = $(LIBNL_LIBS) $(LIBRADIOTAP_LIBS)
endif

if NETBSD
libaircrack_osdep_la_SOURCES = $(SRCS_NBSD)
endif

if OPENBSD
libaircrack_osdep_la_SOURCES = $(SRCS_OBSD)
endif

if !AIRPCAP
libaircrack_osdep_la_LIBADD = $(LIBRADIOTAP_LIBS)
if CYGWIN
libaircrack_osdep_la_LIBADD += -lsetupapi -liphlpapi
endif
endif

lib_LTLIBRARIES = libaircrack-osdep.la
libaircrack_osdep_la_LDFLAGS = -release 1.3.0 -no-undefined

EXTRA_DIST = openbsd.c \
             darwin.c \
             crctable_osdep.h \
             common.c \
             darwin_tap.c \
             cygwin.c \
             aircrack_ng_airpcap.h \
             linux.c \
             file.c \
             network.h \
             osdep.h \
             byteorder.h \
             linux_tap.c \
             common.h \
             airpcap.c \
             cygwin.h \
             netbsd.c \
             packed.h \
             freebsd_tap.c \
             freebsd.c \
             osdep.c \
             dummy_tap.c \
             openbsd_tap.c \
             dummy.c \
             netbsd_tap.c \
             network.c \
             cygwin_tap.c \
             channel.h


@CODE_COVERAGE_RULES@
