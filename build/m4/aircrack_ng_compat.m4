dnl Aircrack-ng
dnl
dnl Copyright (C) 2020-2022 Joseph Benden <joe@benden.us>
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

AC_DEFUN([AIRCRACK_NG_COMPAT], [
AC_ARG_WITH(libbsd,
	[AS_HELP_STRING([--with-libbsd[[=auto|yes|no]]], [use BSD library, [default=auto]])])

AC_CHECK_FUNCS([strlcpy strlcat], [:])

case $with_libbsd in
	yes | "" | auto)
		AC_CHECK_HEADERS([bsd/string.h], [HAVE_BSD_STRING_H=yes])
		AC_CHECK_LIB([bsd], [strlcpy], [:])
		;;
esac

AM_CONDITIONAL([HAVE_BSD_STRING_H], [test "$HAVE_BSD_STRING_H" = yes])

if test $with_libbsd != no
then
	if test $ac_cv_lib_bsd_strlcpy = yes
	then
		LIBS="$LIBS -lbsd"
	elif test $with_libbsd = yes
	then
		AC_MSG_ERROR([cannot configure required bsd library])
	fi
fi

have_bsd=no
if test "$cross_compiling" != yes
then
	AC_RUN_IFELSE([AC_LANG_PROGRAM([
	#include <stdlib.h>
	#include <string.h>
	],[
	#if defined(__APPLE__) && defined(__MACH__)
	exit(0); /* Apple has these as macros */
	#endif
	#ifndef strlcpy
	exit(1);
	#endif
	])], [have_bsd=yes])
fi

AM_CONDITIONAL([INCLUDE_COMPAT_STRLCAT], [test "$ac_cv_func_strlcat" != yes && test "$have_bsd" != yes])
AM_CONDITIONAL([INCLUDE_COMPAT_STRLCPY], [test "$ac_cv_func_strlcpy" != yes && test "$have_bsd" != yes])

])
