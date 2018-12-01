dnl Aircrack-ng
dnl
dnl Copyright (C) 2018 Joseph Benden <joe@benden.us>
dnl
dnl Autotool support was written by: Joseph Benden <joe@benden.us>
dnl
dnl This program is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 2 of the License, or
dnl (at your option) any later version.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, write to the Free Software
dnl Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
dnl
dnl In addition, as a special exception, the copyright holders give
dnl permission to link the code of portions of this program with the
dnl OpenSSL library under certain conditions as described in each
dnl individual source file, and distribute linked combinations
dnl including the two.
dnl
dnl You must obey the GNU General Public License in all respects
dnl for all of the code used other than OpenSSL.
dnl
dnl If you modify file(s) with this exception, you may extend this
dnl exception to your dnl version of the file(s), but you are not obligated
dnl to do so.
dnl
dnl If you dnl do not wish to do so, delete this exception statement from your
dnl version.
dnl
dnl If you delete this exception statement from all source files in the
dnl program, then also delete it here.

AC_DEFUN([AIRCRACK_NG_HWLOC], [
AC_ARG_ENABLE([hwloc],[AC_HELP_STRING([--enable-hwloc], [include hwloc library, [default=yes]])])

HAVE_HWLOC=no

AC_ARG_ENABLE(static-hwloc,
    AS_HELP_STRING([--enable-static-hwloc],
		[Enable statically linked OpenMPI libhwloc.]),
    [static_hwloc=$enableval], [static_hwloc=no])

if test "x$static_hwloc" != "xno"; then
	enable_hwloc=yes
fi

AS_IF([test "x$enable_hwloc" != "xno"], [
	if test "x$static_hwloc" != "xno"; then
		AC_REQUIRE([AX_EXT_HAVE_STATIC_LIB_DETECT])
		AX_EXT_HAVE_STATIC_LIB(HWLOC, ${DEFAULT_STATIC_LIB_SEARCH_PATHS}, hwloc libhwloc, hwloc_bitmap_alloc, -lnuma -lltdl)
		AX_EXT_HAVE_STATIC_LIB(NUMA, ${DEFAULT_STATIC_LIB_SEARCH_PATHS}, numa libnuma, numa_bitmask_setbit, -lltdl)
		AX_EXT_HAVE_STATIC_LIB(LTDL, ${DEFAULT_STATIC_LIB_SEARCH_PATHS}, ltdl libltdl, lt_dlopen, -ldl)
		HWLOC_LIBS="$HWLOC_LIBS $NUMA_LIBS $LTDL_LIBS"
		AC_SUBST([HWLOC_LIBS])
        HAVE_HWLOC=yes
	else
		PKG_CHECK_MODULES(HWLOC, hwloc, HWLOC_FOUND=yes, HWLOC_FOUND=no)
	fi

	AS_IF([test "x$HWLOC_FOUND" = "xyes"], [
		AC_DEFINE([HAVE_HWLOC], [1], [Define if you have hwloc library.])
        HAVE_HWLOC=yes
	])
])

AM_CONDITIONAL([HAVE_HWLOC], [test "$HWLOC_FOUND" = yes])
AM_CONDITIONAL([STATIC_HWLOC], [test "$static_hwloc" != no])
])
