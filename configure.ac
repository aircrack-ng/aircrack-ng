# Aircrack-ng
#
# Copyright (C) 2017 Joseph Benden <joe@benden.us>
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
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

# FIXME: MULTIBIN implementation in here and src/Makefile.am

AC_PREREQ(2.52)
AC_INIT([aircrack-ng],
    [m4_translit(m4_esyscmd([cat $(pwd)/VERSION]),m4_newline)],
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

AM_INIT_AUTOMAKE([1.10 dist-bzip2 dist-zip foreign])
AM_MAINTAINER_MODE([enable])
AC_SUBST([ACLOCAL_AMFLAGS], ["-I build/m4/stubs -I build/m4 \${ACLOCAL_FLAGS}"])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

#
# Find tooling
#
AIRCRACK_NG_PROG_CC
AIRCRACK_NG_PROG_CXX
AC_PROG_INSTALL
AM_PROG_AS

LT_INIT([disable-shared])

#
# Operating Systems
#
AIRCRACK_NG_MAC
AIRCRACK_NG_WINDOWS
AIRCRACK_NG_OS_DETECT

#
# Extra versioning
#
AIRCRACK_NG_REVISION

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
AIRCRACK_NG_ASAN
AIRCRACK_NG_DUMA
AIRCRACK_NG_EXPERIMENTAL
AIRCRACK_NG_EXT_SCRIPTS
AIRCRACK_NG_PCAP
AIRCRACK_NG_PCRE
AIRCRACK_NG_RFKILL
AIRCRACK_NG_SQLITE
AIRCRACK_NG_ZLIB

#
# Extras, but needed
#
AIRCRACK_NG_LARGEFILE
AX_ADD_FORTIFY_SOURCE
AX_PTHREAD([
    AC_CHECK_LIB([pthread], [pthread_create], [ PTHREAD_LIBS="-lpthread" ])
    AC_DEFINE([_REENTRANT])
])
AX_LIB_SOCKET_NSL
AC_CHECK_LIB([dl], [dlopen], [ LIBS="$LIBS -ldl" ], [:])
AC_CHECK_LIB([m], [sin], [ LIBS="$LIBS -lm" ], [:])

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
# Automake
#
AM_CONDITIONAL([HAVE_AIRPCAP_OR_PCAP], [test "$AIRPCAP" = yes -o "$PCAP_FOUND" = yes])
AM_CONDITIONAL([MULTIBIN], [test "$with_multibin" = yes])

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
AC_OUTPUT([
Makefile

manpages/Makefile

scripts/Makefile
scripts/airdrop-ng/Makefile
scripts/airdrop-ng/doc/Makefile
scripts/airgraph-ng/Makefile
scripts/airgraph-ng/man/Makefile
scripts/versuck-ng/Makefile

src/Makefile
src/include/Makefile
src/osdep/Makefile
src/osdep/radiotap/Makefile

test/Makefile
test/test-env.sh
test/cryptounittest/Makefile
])

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

  Crypto Libraries:
    Gcrypt:                      ${GCRYPT_LIBS}
    OpenSSL:                     ${OPENSSL_LIBS}

  Required Libraries:
    Ethtool:                     ${ETHTOOL_FOUND}
    Libnl:                       ${NLLIBNAME_FOUND}

  Optional Libraries:
    Airpcap:                     ${AIRPCAP}
    DUMA:                        ${DUMA}
    Pcap:                        ${PCAP_FOUND}
    Pcre:                        ${HAVE_PCRE}
    Sqlite:                      ${HAVE_SQLITE3}
    Zlib:                        ${HAVE_ZLIB}

  Features:
    Experimental Extra Scripts:  ${EXT_SCRIPTS}
    Experimental Features:       ${EXPERIMENTAL}

EOF
