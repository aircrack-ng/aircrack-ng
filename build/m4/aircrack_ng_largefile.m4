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

AC_DEFUN([_AIRCRACK_NG_LARGEFILE_TEST], [
AC_LANG_PUSH([C++])
AC_CHECK_SIZEOF([off_t])
AC_SYS_LONG_FILE_NAMES
AC_SYS_LARGEFILE
AC_FUNC_FSEEKO
AC_CHECK_SIZEOF([off_t])
AC_LANG_POP([C++])

ac_cv_sizeof_off_t_cpp=$ac_cv_sizeof_off_t
unset ac_cv_sizeof_off_t

AC_LANG_PUSH([C])
AC_CHECK_SIZEOF([off_t])
AC_SYS_LONG_FILE_NAMES
AC_SYS_LARGEFILE
AC_FUNC_FSEEKO
AC_CHECK_SIZEOF([off_t])
AC_LANG_POP([C])

ac_cv_sizeof_off_t_c=$ac_cv_sizeof_off_t
unset ac_cv_sizeof_off_t
])

AC_DEFUN([AIRCRACK_NG_LARGEFILE], [

_AIRCRACK_NG_LARGEFILE_TEST

AS_IF([test ".$ac_cv_sizeof_off_t_c" != ".$ac_cv_sizeof_off_t_cpp"], [
    AS_IF([test $ac_cv_sizeof_off_t_cpp -eq 4], [
        AC_DEFINE([_FILE_OFFSET_BITS], [64], [Define this if 64-bit file access requires this define to be present])
        CXXFLAGS="$CXXFLAGS -D_FILE_OFFSET_BITS=64"
    ])
    AS_IF([test $ac_cv_sizeof_off_t_c -eq 4], [
        AC_DEFINE([_FILE_OFFSET_BITS], [64], [Define this if 64-bit file access requires this define to be present])
        CFLAGS="$CFLAGS -D_FILE_OFFSET_BITS=64"
    ])
    unset ac_cv_sizeof_off_t
    _AIRCRACK_NG_LARGEFILE_TEST
    AS_IF([test ".$ac_cv_sizeof_off_t_c" != ".$ac_cv_sizeof_off_t_cpp"], [
        AC_MSG_ERROR([Cannot figure out how to make C and C++ compilers have the same sized off_t.])
    ])
])

AS_IF([test ".$ac_cv_sys_file_offset_bits$ac_cv_sys_large_files" != ".nono"], [
    AC_DEFINE([_LARGEFILE64_SOURCE], [1], [Define this if 64-bit file access requires this define to be present])
])
])
