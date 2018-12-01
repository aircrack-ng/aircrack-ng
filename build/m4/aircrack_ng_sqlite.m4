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

AC_DEFUN([AIRCRACK_NG_SQLITE],[

AC_ARG_ENABLE(static-sqlite3,
    AS_HELP_STRING([--enable-static-sqlite3],
		[Enable statically linked SQLite3 libsqlite3.]),
    [static_sqlite3=$enableval], [static_sqlite3=no])

if test "x$static_sqlite3" != "xno"; then
	AC_REQUIRE([AX_EXT_HAVE_STATIC_LIB_DETECT])
	AX_EXT_HAVE_STATIC_LIB(SQLITE3, ${DEFAULT_STATIC_LIB_SEARCH_PATHS}, sqlite3 libsqlite3, sqlite3_open, -lpthread -ldl)
	if test "x$SQLITE3_FOUND" = xyes; then
		HAVE_SQLITE3=yes
	fi
else
	AX_LIB_SQLITE3
fi

if test x"$HAVE_SQLITE3" = xyes; then
    AC_DEFINE([HAVE_SQLITE], [1], [Define if you have sqlite3])
    HAVE_SQLITE3=yes
else
    HAVE_SQLITE3=no
fi

AM_CONDITIONAL([HAVE_SQLITE3], [test "$HAVE_SQLITE3" = yes])
])
