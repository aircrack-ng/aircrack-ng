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
dnl Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

AC_DEFUN([AIRCRACK_NG_LIBNL], [
AC_ARG_ENABLE([libnl],[AC_HELP_STRING([--enable-libnl], [include netlink library, [default=yes on Linux]])])
_aircrack_ng_enable_libnl=no

case "$host_os" in
    LINUX* | linux*)
        _aircrack_ng_enable_libnl=yes
        ;;
esac

case "$_aircrack_ng_enable_libnl" in
    yes)
        case "$enable_libnl" in
            yes | "" | auto)
                PKG_CHECK_MODULES([LIBNL3X], [libnl-3.0 >= 3.2], [
                    # CPPFLAGS="$CPPFLAGS $LIBNL3X_CFLAGS -DCONFIG_LIBNL30 -DCONFIG_LIBNL"
                    # LIBS="$LIBS $LIBNL3X_LIBS -lnl-genl-3"
                    LIBNL_CFLAGS="$LIBNL3X_CFLAGS -DCONFIG_LIBNL30 -DCONFIG_LIBNL"
                    LIBNL_LIBS="$LIBNL3X_LIBS -lnl-genl-3"
                    NLLIBNAME="libnl-3.0"
                ], [
                    PKG_CHECK_MODULES([LIBNL31], [libnl-3.1 = 3.1], [
                        LIBNL_CFLAGS="$LIBNL31_CFLAGS -DCONFIG_LIBNL30 -DCONFIG_LIBNL"
                        LIBNL_LIBS="$LIBNL31_LIBS -lnl-genl"
                        NLLIBNAME="libnl-3.1"
                    ], [
                        PKG_CHECK_MODULES([LIBNL30], [libnl-3.0 >= 3], [
                            LIBNL_CFLAGS="$LIBNL30_CFLAGS -DCONFIG_LIBNL30 -DCONFIG_LIBNL"
                            LIBNL_LIBS="$LIBNL30_LIBS -lnl-genl"
                            NLLIBNAME="libnl-3.0"
                        ], [
                            PKG_CHECK_MODULES([LIBNL1], [libnl-1 >= 1], [
                                LIBNL_CFLAGS="$LIBNL1_CFLAGS -DCONFIG_LIBNL"
                                LIBNL_LIBS="$LIBNL1_LIBS"
                                NLLIBNAME="libnl-1"
                            ], [
                                PKG_CHECK_MODULES([LIBNLT], [libnl-tiny >= 1], [
                                    LIBNL_CFLAGS="$LIBNLT_CFLAGS -DCONFIG_LIBNL -DCONFIG_LIBNL20"
                                    LIBNL_LIBS="$LIBNLT_LIBS"
                                    NLLIBNAME="libnl-tiny"
                                ], [
                                    AC_MSG_RESULT([could not find development files for any supported version of libnl. install either libnl1 or libnl3.])
                                    NLLIBNAME=""
                                ])
                            ])
                        ])
                    ])
                ])

                AC_SUBST([LIBNL_CFLAGS])
                AC_SUBST([LIBNL_LIBS])
                AC_SUBST([NLLIBNAME])

                if test "x$NLLIBNAME" = x; then
                    NLLIBNAME_FOUND="no"
                else
                    NLLIBNAME_FOUND="yes, found $NLLIBNAME"
                fi
                ;;
            *)
                NLLIBNAME_FOUND="not enabled"
                ;;
        esac
        ;;
    *)
        NLLIBNAME_FOUND="not required"
        ;;
esac
])
