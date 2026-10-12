dnl Aircrack-ng
dnl
dnl Copyright (C) 2017 Joseph Benden <joe@benden.us>
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

AC_DEFUN([AIRCRACK_NG_PCRE], [
AC_ARG_ENABLE(static-pcre,
    AS_HELP_STRING([--enable-static-pcre],
		[Enable statically linked PCRE libpcre.]),
    [static_pcre=$enableval], [static_pcre=no])

if test "x$static_pcre" != "xno"; then
	AC_REQUIRE([AX_EXT_HAVE_STATIC_LIB_DETECT])
	AX_EXT_HAVE_STATIC_LIB(PCRE, ${DEFAULT_STATIC_LIB_SEARCH_PATHS}, pcre libpcre, pcre_version)
	if test "x$PCRE_FOUND" = xyes; then
		HAVE_PCRE=yes
	else
		HAVE_PCRE=no
	fi
else
	PKG_CHECK_MODULES(PCRE, libpcre, HAVE_PCRE=yes, HAVE_PCRE=no)
fi

AC_ARG_ENABLE(static-pcre2,
    AS_HELP_STRING([--enable-static-pcre2],
		[Enable statically linked PCRE2 libpcre2-8.]),
    [static_pcre2=$enableval], [static_pcre2=no])

if test "x$static_pcre2" != "xno"; then
	AC_REQUIRE([AX_EXT_HAVE_STATIC_LIB_DETECT])
	AX_EXT_HAVE_STATIC_LIB(PCRE2, ${DEFAULT_STATIC_LIB_SEARCH_PATHS}, pcre2 libpcre2-8, pcre2_version)
	if test "x$PCRE2_FOUND" = xyes; then
		HAVE_PCRE2=yes
	else
		HAVE_PCRE2=no
	fi
else
	PKG_CHECK_MODULES(PCRE2, libpcre2-8, HAVE_PCRE2=yes, HAVE_PCRE2=no)
fi

if test "x$HAVE_PCRE" = "xyes" && test "x$HAVE_PCRE2" = "xyes"; then
    AC_DEFINE([HAVE_PCRE2], [1], [Define this if you have libpcre2-8 on your system])
    PCRE2_NOTE="(Pcre and Pcre2 found, using Pcre2)"
    # Reset PCRE cflags and libs variables as we include both PCRE and PCRE2 in Makefile.inc
    # and would result in trying to link/include both library.
    PCRE_CFLAGS=""
    PCRE_LIBS=""
elif test "x$HAVE_PCRE" = "xyes"; then
    AC_DEFINE([HAVE_PCRE], [1], [Define this if you have libpcre on your system])
elif test "x$HAVE_PCRE2" = "xyes"; then
    AC_DEFINE([HAVE_PCRE2], [1], [Define this if you have libpcre2-8 on your system])
fi
])