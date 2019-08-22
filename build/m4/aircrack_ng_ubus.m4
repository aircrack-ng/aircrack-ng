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

AC_DEFUN([AIRCRACK_NG_UBUS], [
AC_ARG_ENABLE(ubus, AS_HELP_STRING([--enable-ubus], [Enable UBUS support]), [UBUS_SUPPORT=yes], [UBUS_SUPPORT=no])

AC_ARG_WITH(libubus-include,
    [AS_HELP_STRING([--with-libubus-include=DIR],
        [use UBUS includes in DIR, [default=auto]])
    ],[
    	if test -d "$withval" ; then
    		CPPFLAGS="$CPPFLAGS -I$withval"
    	fi
    ])

AC_ARG_WITH(libubus-lib,
    [AS_HELP_STRING([--with-libubus-lib=DIR],
        [use UBUS libraries in DIR, [default=auto]])
    ],[
    	if test -d "$withval" ; then
    		LDFLAGS="$LDFLAGS -L$withval"
    	fi
    ])

dnl
dnl Search for headers
dnl
if test "${with_libubus_include+set}" != set; then
	AC_MSG_CHECKING(ubus header directories)

	found_ubus_dir=""
	for ubus_dir in /usr/include /usr/local/include \
					$prefix/include ; do
		if test -e "${ubus_dir+/libubus.h}" ; then
			found_ubus_dir="$ubus_dir"
			break
		fi
	done

	if test "$found_ubus_dir" != "" ; then
		UBUS_CFLAGS="-I$found_ubus_dir"
		AC_SUBST([UBUS_CFLAGS])

		AC_MSG_RESULT([$found_ubus_dir])
	else
		AC_MSG_RESULT([not found])
	fi
fi

dnl
dnl Verify that required headers are useable
dnl
saved_cflags="$CFLAGS"
CFLAGS="$UBUS_INCLUDES $CFLAGS"
AC_CHECK_HEADERS([libubus.h], [
	UBUS_SUPPORT=yes
], [
	UBUS_SUPPORT=no
])
CFLAGS="$saved_cflags"


dnl
dnl Locate the library
dnl
AS_IF([test "$UBUS_SUPPORT" = yes], [
	AC_SEARCH_LIBS([ubus_connect], [ubus], [
		UBUS_LIBS=-lubus
		AC_SUBST(UBUS_LIBS)
		AC_DEFINE([INCLUDE_UBUS], [1], [Define this if you want ubus event support])
	])
	AC_SEARCH_LIBS([uloop_init], [ubox], [
		UBOX_LIBS=-lubox
		AC_SUBST(UBOX_LIBS)
	])
])

AM_CONDITIONAL([UBUS_SUPPORT], [test "$UBUS_SUPPORT" = yes])
])
