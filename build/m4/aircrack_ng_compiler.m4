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

AC_DEFUN([AIRCRACK_NG_COMPILER], [
AX_REQUIRE_DEFINED([AX_COMPILER_VENDOR])
AX_REQUIRE_DEFINED([AX_COMPILER_VERSION])
AX_REQUIRE_DEFINED([AX_COMPARE_VERSION])
AX_REQUIRE_DEFINED([AX_CHECK_COMPILE_FLAG])
AX_REQUIRE_DEFINED([AX_CFLAGS_WARN_ALL])
AX_REQUIRE_DEFINED([AX_CXXFLAGS_WARN_ALL])
AX_REQUIRE_DEFINED([AX_APPEND_FLAG])

AX_COMPILER_VENDOR
AX_COMPILER_VERSION

saved_cflags="$CFLAGS"
CFLAGS=""
AX_CFLAGS_WARN_ALL
AX_APPEND_FLAG($CFLAGS, [opt_cflags])
CFLAGS="$saved_cflags"

saved_cxxflags="$CXXFLAGS"
CXXFLAGS=""
AX_CXXFLAGS_WARN_ALL
AX_APPEND_FLAG($CXXFLAGS, [opt_cxxflags])
CXXFLAGS="$saved_cxxflags"

AC_ARG_WITH(opt,
    [AS_HELP_STRING([--without-opt],
        [disable -O3 optimizations])])

AS_IF([test "x$enable_code_coverage" = "xno"], [
    case $with_opt in
        yes | "")
            AX_CHECK_COMPILE_FLAG([-O3], [
                AX_APPEND_FLAG(-O3, [opt_[]_AC_LANG_ABBREV[]flags])
            ])
        ;;
    esac
])

AC_LANG_CASE([C], [
    saved_cflags="$CFLAGS"
    AX_CHECK_COMPILE_FLAG([-std=gnu99], [
        AX_APPEND_FLAG(-std=gnu99, [opt_[]_AC_LANG_ABBREV[]flags])
    ])
])

case "$ax_cv_[]_AC_LANG_ABBREV[]_compiler_vendor" in
    gnu|clang|intel)
        AX_COMPARE_VERSION([$ax_cv_[]_AC_LANG_ABBREV[]_compiler_version], [ge], [4.1], [gcc_over41=yes], [gcc_over41=x])
        AX_COMPARE_VERSION([$ax_cv_[]_AC_LANG_ABBREV[]_compiler_version], [ge], [4.5], [gcc_over45=yes], [gcc_over45=x])
        AX_COMPARE_VERSION([$ax_cv_[]_AC_LANG_ABBREV[]_compiler_version], [ge], [4.9], [gcc_over49=yes], [gcc_over49=x])
    ;;
esac

dnl
dnl Enable compiler flags that meet the required minimum version
dnl
case "$ax_cv_[]_AC_LANG_ABBREV[]_compiler_vendor" in
    gnu|clang)
        AS_IF([test "x$gcc_over49" = "xno"], [
            AS_IF([test "x$gcc_over41" = "xyes"], [
                AX_CHECK_COMPILE_FLAG([-fstack-protector], [
                    AX_APPEND_FLAG(-fstack-protector, [opt_[]_AC_LANG_ABBREV[]flags])
                ])
            ], [])
        ], [])

        AS_IF([test "x$gcc_over49" = "xyes"], [
            AX_CHECK_COMPILE_FLAG([-fstack-protector-strong], [
                AX_APPEND_FLAG(-fstack-protector-strong, [opt_[]_AC_LANG_ABBREV[]flags])
            ])
        ], [])
        ;;
esac

AS_IF([test "x$gcc_over45" = "xyes"], [
    AX_CHECK_COMPILE_FLAG([-Wno-unused-but-set-variable], [
        AX_APPEND_FLAG(-Wno-unused-but-set-variable, [opt_[]_AC_LANG_ABBREV[]flags])
    ])
    AX_CHECK_COMPILE_FLAG([-Wno-array-bounds], [
        AX_APPEND_FLAG(-Wno-array-bounds, [opt_[]_AC_LANG_ABBREV[]flags])
    ])
], [])
])

AC_DEFUN([AIRCRACK_NG_COMPILER_C], [
AC_LANG_PUSH([C])
AIRCRACK_NG_COMPILER
AC_LANG_POP([C])
])

AC_DEFUN([AIRCRACK_NG_COMPILER_CXX], [
AC_LANG_PUSH([C++])
AIRCRACK_NG_COMPILER
AC_LANG_POP([C++])
])
