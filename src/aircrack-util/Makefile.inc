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

if ARM
TRAMPOLINE = %D%/trampoline_arm.c
endif
if PPC
TRAMPOLINE = %D%/trampoline_ppc.c
endif
if X86
TRAMPOLINE = %D%/trampoline_x86.c
endif

if !ARM
if !PPC
if !X86
TRAMPOLINE = %D%/trampoline_stubs.c
endif
endif
endif

if HAVE_HWLOC
CPUSET = %D%/cpuset_hwloc.c
endif
if !HAVE_HWLOC
CPUSET = %D%/cpuset_pthread.c
endif

libaircrack_util_la_SOURCES = %D%/circular_buffer.c \
                              %D%/circular_queue.c \
                              %D%/common.c \
                              %D%/console.c \
                              %D%/crypto_engine_loader.c \
                              %D%/mcs_index_rates.c \
                              %D%/simd_cpuid.c \
                              $(TRAMPOLINE) \
                              %D%/verifyssid.c \
                              %D%/avl_tree.c \
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

noinst_LTLIBRARIES += libaircrack-util.la

EXTRA_DIST +=     %D%/circular_buffer.c \
                  %D%/circular_buffer.h \
                  %D%/circular_queue.c \
                  %D%/circular_queue.h \
                  %D%/common.c \
                  %D%/common.h \
                  %D%/console.c \
                  %D%/console.h \
                  %D%/cpuset.h \
                  %D%/cpuset_hwloc.c \
                  %D%/cpuset_pthread.c \
                  %D%/crypto_engine_loader.c \
                  %D%/crypto_engine_loader.h \
                  %D%/mcs_index_rates.c \
                  %D%/mcs_index_rates.h \
                  %D%/simd_cpuid.c \
                  %D%/simd_cpuid.h \
                  %D%/trampoline.c \
                  %D%/trampoline.h \
                  %D%/trampoline_x86.c \
                  %D%/trampoline_arm.c \
                  %D%/trampoline_ppc.c \
                  %D%/trampoline_stubs.c \
                  %D%/verifyssid.c \
                  %D%/verifyssid.h \
                  %D%/avl_tree.c \
                  %D%/avl_tree.h
