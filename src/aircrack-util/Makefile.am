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
              $(LIBNL_CFLAGS)

LIBAIRCRACK_CRYPTO_PATH = $(abs_top_builddir)/src/aircrack-crypto/

if ARM
TRAMPOLINE = trampoline_arm.c
endif
if PPC
TRAMPOLINE = trampoline_ppc.c
endif
if X86
TRAMPOLINE = trampoline_x86.c
endif

if !ARM
if !PPC
if !X86
TRAMPOLINE = trampoline_stubs.c
endif
endif
endif

if HAVE_HWLOC
CPUSET = cpuset_hwloc.c
endif
if !HAVE_HWLOC
CPUSET = cpuset_pthread.c
endif

libaircrack_util_la_SOURCES = common.c \
							  console.c \
							  crypto_engine_loader.c \
							  mcs_index_rates.c \
							  simd_cpuid.c \
							  $(TRAMPOLINE) \
							  verifyssid.c \
							  avl_tree.c \
							  $(CPUSET)
libaircrack_util_la_CFLAGS  = "-DLIBAIRCRACK_CRYPTO_PATH=\"$(LIBAIRCRACK_CRYPTO_PATH)\"" \
                              "-DABS_TOP_SRCDIR=\"$(abs_top_srcdir)\"" \
                              "-DABS_TOP_BUILDDIR=\"$(abs_top_builddir)\"" \
                              "-DLIBDIR=\"$(libdir)\""
if CYGWIN
libaircrack_util_la_LIBADD = -lshlwapi
endif

if STATIC_BUILD
libaircrack_util_la_CFLAGS += -DSTATIC_BUILD
endif

if HAVE_HWLOC
libaircrack_util_la_CFLAGS += $(HWLOC_CFLAGS)
if !CYGWIN
if !STATIC_HWLOC
libaircrack_util_la_LIBADD = $(HWLOC_LIBS)
endif
endif
if CYGWIN
if !STATIC_HWLOC
libaircrack_util_la_LIBADD += $(HWLOC_LIBS)
endif
endif
endif

noinst_LTLIBRARIES = libaircrack-util.la

EXTRA_DIST = common.c \
             common.h \
             console.c \
             console.h \
			 cpuset.h \
			 cpuset_hwloc.c \
			 cpuset_pthread.c \
             crypto_engine_loader.c \
             crypto_engine_loader.h \
             mcs_index_rates.c \
             mcs_index_rates.h \
             simd_cpuid.c \
             simd_cpuid.h \
             trampoline.c \
             trampoline.h \
             trampoline_x86.c \
             trampoline_arm.c \
             trampoline_ppc.c \
             trampoline_stubs.c \
             verifyssid.c \
             verifyssid.h \
			 avl_tree.c \
			 avl_tree.h


@CODE_COVERAGE_RULES@
