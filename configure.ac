# Aircrack-ng
#
# Copyright (C) 2017-2020 Joseph Benden <joe@benden.us>
#
# Autotool support was written by: Joseph Benden <joe@benden.us>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
#
# In addition, as a special exception, the copyright holders give
# permission to link the code of portions of this program with the
# OpenSSL library under certain conditions as described in each
# individual source file, and distribute linked combinations
# including the two.
#
# You must obey the GNU General Public License in all respects
# for all of the code used other than OpenSSL.
#
# If you modify file(s) with this exception, you may extend this
# exception to your # version of the file(s), but you are not obligated
# to do so.
#
# If you # do not wish to do so, delete this exception statement from your
# version.
#
# If you delete this exception statement from all source files in the
# program, then also delete it here.

m4_define([version_date], "January 2020")
m4_define([version_major], 1)
m4_define([version_minor], 6)
m4_define([version_micro], 0)
m4_define([version_beta],  0)
m4_define([version_rc],    0)
m4_define([version_scm],[m4_translit(m4_esyscmd([$(pwd)/evalrev . scm || echo]),m4_newline)])
m4_define([version_triplet],version_major.version_minor.version_micro)
m4_append([version_triplet],version_scm)

AC_PREREQ([2.52])
AC_INIT([aircrack-ng],
    [version_triplet],
    [https://forum.aircrack-ng.org])

#
# Cross-Compilation
#
AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

#
# Initialize Automake
#
AC_CONFIG_AUX_DIR([.])
AC_CONFIG_MACRO_DIR([build/m4/stubs])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([1.14 dist-bzip2 dist-zip foreign subdir-objects])
AM_MAINTAINER_MODE([enable])
AC_SUBST([ACLOCAL_AMFLAGS], ["-I build/m4/stubs -I build/m4 \${ACLOCAL_FLAGS}"])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

#
# Ensure MAKE is GNU compatible
#
if ! ${MAKE-make} --version /cannot/make/this >/dev/null 2>&1; then
    AC_MSG_ERROR([you don't seem to have GNU make; it is required])
fi

#
# Find tooling
#
AIRCRACK_NG_PROG_CC
AIRCRACK_NG_PROG_CXX
AC_PROG_INSTALL
AM_PROG_AS
PKG_PROG_PKG_CONFIG
AM_PROG_CC_C_O

#
# Set versioning detail
#
AC_SUBST([_MAJ], [version_major])
AC_SUBST([_MIN], [version_minor])
AC_SUBST([_SUB_MIN], [version_micro])
AC_SUBST([_BETA], [version_beta])
AC_SUBST([_RC], [version_rc])
AC_SUBST([_SCM], [version_scm])
AC_SUBST([LT_VER], [version_major.version_minor.version_micro])
AC_SUBST([MAN_RELEASE_DATE], [version_date])
AC_SUBST([MAN_RELEASE_VERSION], ["Version version_triplet"])
AC_DEFINE([_REVISION], ["version_triplet"], [The version information of the project])
AC_DEFINE([LT_CYGWIN_VER], ["-version_major-version_minor-version_micro.dll"], [The Cygwin DLL version string suffix])

#
# Initialize libtool
#
LT_INIT([win32-dll disable-static shared])

#
# Operating Systems
#
AIRCRACK_NG_MAC
AIRCRACK_NG_WINDOWS
AIRCRACK_NG_OS_DETECT

#
# Required
#
AIRCRACK_NG_CRYPTO
AIRCRACK_NG_ETHTOOL
AIRCRACK_NG_LIBNL

#
# Optional
#
AIRCRACK_NG_AIRPCAP
AIRCRACK_NG_EXPECT
AIRCRACK_NG_EXPERIMENTAL
AIRCRACK_NG_EXT_SCRIPTS
AIRCRACK_NG_HWLOC
AIRCRACK_NG_PCAP
AIRCRACK_NG_PCRE
AIRCRACK_NG_RFKILL
AIRCRACK_NG_SQLITE
AIRCRACK_NG_ZLIB
PKG_CHECK_MODULES([CMOCKA], [cmocka], [
		CMOCKA_FOUND=yes
		AC_SUBST([CMOCKA_CFLAGS])
		AC_SUBST([CMOCKA_LIBS])
	], [CMOCKA_FOUND=no])

#
# Extras, but needed
#
AIRCRACK_NG_LARGEFILE
AX_ADD_FORTIFY_SOURCE
AIRCRACK_NG_PTHREAD
AX_LIB_SOCKET_NSL
AC_CHECK_LIB([dl], [dlopen], [ LIBS="$LIBS -ldl" ], [:])
AC_CHECK_LIB([m], [sin], [ LIBS="$LIBS -lm" ], [:])
saved_cflags="$CFLAGS"
CFLAGS=""
AC_CHECK_FUNCS([posix_memalign aligned_alloc memalign __mingw_aligned_malloc _aligned_malloc], break)
CFLAGS="$saved_cflags"

#
# Code Coverage Support
#
AIRCRACK_NG_CODE_COVERAGE

#
# Valgrind Support
#
AX_VALGRIND_CHECK

#
# Compiler set-up
#
AIRCRACK_NG_COMPILER_C
AIRCRACK_NG_COMPILER_CXX

#
# Processor feature selection/detection
#
AIRCRACK_NG_SIMD_C
AIRCRACK_NG_SIMD_CXX

#
# Optional analyzers
#
AIRCRACK_NG_ASAN
AIRCRACK_NG_DUMA
AIRCRACK_NG_JEMALLOC
AIRCRACK_NG_TCMALLOC
AIRCRACK_NG_TSAN

#
# Automake
#
AM_CONDITIONAL([HAVE_AIRPCAP_OR_PCAP], [test "$AIRPCAP" = yes -o "$PCAP_FOUND" = yes])
AM_CONDITIONAL([MULTIBIN], [test "$with_multibin" = yes])
AM_CONDITIONAL([ENABLE_INSTALLED_TESTS], [test "nope" = yes]) # for glib tests
AM_CONDITIONAL([CMOCKA], [test "$CMOCKA_FOUND" = yes])
AM_CONDITIONAL([STATIC_BUILD], [test "$enable_static" = yes])
AM_CONDITIONAL([EXPECT], [test "$EXPECT_FOUND" = yes])

#
# Save flags for build summary
#
summary_cflags="$CFLAGS"
summary_cxxflags="$CXXFLAGS"
summary_cppflags="$CPPFLAGS"
summary_libs="$LIBS"

#
# Set final flags for build
#
CFLAGS="$opt_cflags $CFLAGS"
CPPFLAGS="$opt_cppflags $CPPFLAGS"
CXXFLAGS="$opt_cxxflags $CXXFLAGS"
LIBS="$opt_libs $LIBS"

#
# Generate all build files
#
AC_CONFIG_FILES([
Makefile
VERSION

include/aircrack-ng/version.h

manpages/airbase-ng.8
manpages/aircrack-ng.1
manpages/airdecap-ng.1
manpages/airdecloak-ng.1
manpages/aireplay-ng.8
manpages/airmon-ng.8
manpages/airodump-ng.8
manpages/airodump-ng-oui-update.8
manpages/airolib-ng.1
manpages/airserv-ng.8
manpages/airtun-ng.8
manpages/airventriloquist-ng.8
manpages/besside-ng.8
manpages/besside-ng-crawler.1
manpages/buddy-ng.1
manpages/easside-ng.8
manpages/ivstools.1
manpages/kstats.1
manpages/Makefile
manpages/makeivs-ng.1
manpages/packetforge-ng.1
manpages/tkiptun-ng.8
manpages/wesside-ng.8
manpages/wpaclean.1

scripts/Makefile
scripts/airdrop-ng/Makefile
scripts/airdrop-ng/doc/Makefile
scripts/airgraph-ng/Makefile
scripts/airgraph-ng/man/Makefile
scripts/versuck-ng/Makefile

test/test-env.sh
])
AC_OUTPUT

#
# Output a summary of the build to be performed
#
cat <<EOF

${PACKAGE} ${VERSION}

  Build Environment:
    Build Machine:               ${build}
    Host Machine:                ${host}
    Target Machine:              ${target}

    Install Prefix:              ${prefix}

  Compiler Environment:
    C Compiler:                  ${CC}
    C++ Compiler:                ${CXX}
    Python:                      ${PYTHON}

    CFLAGS:                      ${summary_cflags}
    CXXFLAGS:                    ${summary_cxxflags}
    CPPFLAGS:                    ${summary_cppflags}
    LDFLAGS:                     ${LDFLAGS}
    LIBS:                        ${summary_libs}

    Optimized CFLAGS:            ${opt_cflags}
    Optimized CXXFLAGS:          ${opt_cxxflags}
    Optimized CPPFLAGS:          ${opt_cppflags}
    Optimized LIBS:              ${opt_libs}

  Target Environment:
    OS:                          ${OS}
    ASAN:                        ${asan}
    CPU L1 cache-line size:      ${CACHELINE_SIZE}

  Crypto Libraries:
    Crypto Engine:               ${CRYPTO_TYPE}
    Gcrypt:                      ${GCRYPT_LIBS}
    OpenSSL:                     ${OPENSSL_LIBS}

  Required Libraries:
    Ethtool:                     ${ETHTOOL_FOUND}
    Libnl:                       ${NLLIBNAME_FOUND}

  Optional Libraries:
    Airpcap:                     ${AIRPCAP}
    Cmocka:                      ${CMOCKA_FOUND}
    DUMA:                        ${DUMA}
    Hwloc:                       ${HAVE_HWLOC}
    Jemalloc:                    ${JEMALLOC}
    Pcap:                        ${PCAP_FOUND}
    Pcre:                        ${HAVE_PCRE}
    Sqlite:                      ${HAVE_SQLITE3}
    Tcmalloc:                    ${TCMALLOC}
    Zlib:                        ${HAVE_ZLIB}

  Features:
    CMAC Support:                ${HAVE_CMAC}
    Experimental Extra Scripts:  ${EXT_SCRIPTS}
    Experimental Features:       ${EXPERIMENTAL}

EOF
