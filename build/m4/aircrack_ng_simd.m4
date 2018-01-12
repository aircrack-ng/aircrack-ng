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

AC_DEFUN([AIRCRACK_NG_SIMD_AUTODETECT], [
case "$host_cpu" in
    x86_64 | amd64 | i*86*)
        AX_GCC_X86_CPU_SUPPORTS([avx], [
            AVX1FLAG=Y
            SIMDCORE=true
        ]) # SIMDSIZE=8

        AX_GCC_X86_CPU_SUPPORTS([avx2], [
            AVX2FLAG=Y
            SIMDCORE=true
        ]) # SIMDSIZE=16

        AX_GCC_X86_CPU_SUPPORTS([sse2], [
            SSEFLAG=Y
        ]) # SIMDSIZE=4

        AX_GCC_X86_CPU_SUPPORTS([mmx], [
            MMXFLAG=Y
        ]) # SIMDSIZE=1

        IS_X86=1
        ;;

    *arm* | *aarch64*)
        IS_ARM=1
        NEON_FLAG=$(grep -cE '(neon|asimd)' /proc/cpuinfo)
        ;;

    *)
        NEWSSE=false
        ;;
esac
])

AC_DEFUN([AIRCRACK_NG_SIMD], [
AX_REQUIRE_DEFINED([AX_COMPILER_VENDOR])
AX_REQUIRE_DEFINED([AX_COMPILER_VERSION])
AX_REQUIRE_DEFINED([AX_CHECK_COMPILE_FLAG])
AX_REQUIRE_DEFINED([AX_APPEND_FLAG])

AX_COMPILER_VENDOR
AX_COMPILER_VERSION

OPENBSD=0
IS_X86=0
IS_ARM=0
IS_PPC=0
IS_CROSS=0
SIMDSIZE=0
SIMDFLAG=""
NEWSSE=true
SIMDCORE=false

if test "$cross_compiling" != yes
then
    IS_CROSS=0
else
    IS_CROSS=1
fi

case "$host_cpu" in
    x86_64 | amd64 | i*86*)
        IS_X86=1
        ;;
    *arm* | *aarch64*)
        IS_ARM=1
        ;;
    *mips*)
        IS_MIPS=1
        ;;
    powerpc*)
        IS_PPC=1
        ;;
esac

case "$host_os" in
    *openbsd* | *OpenBSD*)
        OPENBSD=1
        ;;
esac

AC_ARG_WITH(simd,
    [AS_HELP_STRING([--with-simd[[=auto|sse2|avx|avx2|mmx|neon]]],
        [use SIMD extensions, [default=auto]])])

case $with_simd in
    neon)
        IS_ARM=1
        NEON_FLAG=1
        SIMDCORE=true
        with_simd=neon
        ;;
    avx2)
        IS_X86=1
        AVX2FLAG=Y
        SIMDCORE=true
        ;;
    avx | avx1)
        IS_X86=1
        AVX1FLAG=Y
        SIMDCORE=true
        ;;
    sse2)
        IS_X86=1
        SSEFLAG=Y
        ;;
    mmx)
        IS_X86=1
        MMXFLAG=Y
        ;;
    "" | auto)
        AS_IF([test "$cross_compiling" = no], [
            AIRCRACK_NG_SIMD_AUTODETECT
        ], [
            AC_MSG_ERROR([Cannot auto-detect SIMD extensions when cross-compiling, please disable or set to a valid option.])
        ])
        ;;
esac

AS_IF([test $OPENBSD -eq 0], [
    AC_LANG_CASE([C++], [
        AX_CHECK_COMPILE_FLAG([-masm=intel], [
            AX_APPEND_FLAG(-masm=intel, [opt_cxxflags])
            AC_DEFINE([INTEL_ASM], [1], [Define if Intel assembly style is supported])
        ])
    ])
])

if test $IS_ARM -eq 1
then
    if test $NEON_FLAG -eq 1
    then
        case "$host_cpu" in
            *arm*)
                AX_CHECK_COMPILE_FLAG([-mfpu=neon], [
                    AX_APPEND_FLAG(-mfpu=neon, [opt_[]_AC_LANG_ABBREV[]flags])
                    AC_DEFINE([HAS_NEON], [1], [Define if neon instructions are supported])
                    SIMDCORE=true
                    with_simd=neon
                ])
                ;;
            aarch64*)
                AC_DEFINE([HAS_NEON], [1], [Define if ASIMD/NEON instructions are supported])
                SIMDCORE=true
                with_simd=neon
                ;;
        esac
    fi
fi

if test $IS_X86 -eq 0
then
    AC_CHECK_HEADERS([sys/auxv.h], [
        AC_DEFINE([HAS_AUXV], [1], [Define if your system has sys/auxv.h header])
    ])
fi

if test "$cross_compiling" != no
then
    case "$with_simd" in
        no)
            NEWSSE=false
            ;;
    esac
fi

if test "$NEWSSE" = false ; then
    AX_APPEND_FLAG(-DOLD_SSE_CORE=1, [opt_cppflags])
fi

if test "$AVX2FLAG" = Y ; then
    with_simd=avx2
    case "$ax_cv_[]_AC_LANG_ABBREV[]_compiler_vendor" in
        intel)
            AX_APPEND_FLAG(-march=core-avx2, [opt_[]_AC_LANG_ABBREV[]flags])
            AX_APPEND_FLAG(-DJOHN_AVX2, [opt_cppflags])
            ;;
        *)
            AX_APPEND_FLAG(-mavx2, [opt_[]_AC_LANG_ABBREV[]flags])
            AX_APPEND_FLAG(-DJOHN_AVX2, [opt_cppflags])
            ;;
    esac
else
    if test "$AVX1FLAG" = Y ; then
        with_simd=avx
        case "$ax_cv_[]_AC_LANG_ABBREV[]_compiler_vendor" in
            intel)
                AX_APPEND_FLAG(-march=corei7-avx, [opt_[]_AC_LANG_ABBREV[]flags])
                AX_APPEND_FLAG(-DJOHN_AVX, [opt_cppflags])
                ;;
            *)
                AX_APPEND_FLAG(-mavx, [opt_[]_AC_LANG_ABBREV[]flags])
                AX_APPEND_FLAG(-DJOHN_AVX, [opt_cppflags])
                ;;
        esac
    else
        if test "$SSEFLAG" = Y ; then
            with_simd=sse2
            case "$ax_cv_[]_AC_LANG_ABBREV[]_compiler_vendor" in
                intel)
                    AX_APPEND_FLAG(-march=corei7, [opt_[]_AC_LANG_ABBREV[]flags])
                    ;;
                *)
                    AX_APPEND_FLAG(-msse2, [opt_[]_AC_LANG_ABBREV[]flags])
                    ;;
            esac
        else
            if test "$MMXFLAG" = Y ; then
                with_simd=mmx
                case "$ax_cv_[]_AC_LANG_ABBREV[]_compiler_vendor" in
                    intel)
                        AX_APPEND_FLAG(-march=pentiumii, [opt_[]_AC_LANG_ABBREV[]flags])
                        ;;
                    *)
                        AX_APPEND_FLAG(-mmmx, [opt_[]_AC_LANG_ABBREV[]flags])
                        ;;
                esac
            fi
        fi
    fi
fi

AM_CONDITIONAL([NEWSSE], [test "$NEWSSE" = true])
AM_CONDITIONAL([SIMDCORE], [test "$SIMDCORE" = true])
])

AC_DEFUN([AIRCRACK_NG_SIMD_C], [
AC_LANG_PUSH([C])
AIRCRACK_NG_SIMD
AC_LANG_POP([C])
])

AC_DEFUN([AIRCRACK_NG_SIMD_CXX], [
AC_LANG_PUSH([C++])
AIRCRACK_NG_SIMD
AC_LANG_POP([C++])
])
