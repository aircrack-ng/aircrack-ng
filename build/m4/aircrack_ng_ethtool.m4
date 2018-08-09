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

AC_DEFUN([AIRCRACK_NG_ETHTOOL],[
case "$target" in
  *-linux-*)
AC_ARG_VAR([ETHTOOL],[Use this ethtool for Airmon-ng.])
dnl Allow env override but do not be fooled by 'ETHTOOL=t'.
test t = "$ETHTOOL" && unset ETHTOOL
AC_CHECK_PROG([ETHTOOL], [ethtool], [$as_dir/$ac_word$ac_exec_ext], [], [$ETHTOOL_PATH$PATH_SEPARATOR$PATH$PATH_SEPARATOR/sbin$PATH_SEPARATOR/usr/sbin$PATH_SEPARATOR/usr/local/sbin])
AS_IF([test "x$ETHTOOL" = "x"],[
    AC_MSG_WARN([ethtool not found; cannot build Airmon-ng])
    ETHTOOL_FOUND="not found, skipping Airmon-ng"
], [
    ETHTOOL_FOUND="yes, found $ETHTOOL"
])
  ;;
  *)
ETHTOOL_FOUND="not required"
  ;;
esac
])
