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

AC_DEFUN([AIRCRACK_NG_MAC],[
AX_REQUIRE_DEFINED([AC_CHECK_HEADER])[]dnl
AX_REQUIRE_DEFINED([AC_CHECK_FILE])[]dnl

AC_ARG_WITH(xcode,
    [AS_HELP_STRING([--with-xcode], [enable XCode support])])

case "$host_os" in
    DARWIN*|MACOS*|darwin*|macos*)
    	dnl
        dnl Homebrew
        dnl

	AC_ARG_VAR([BREW],[Use this brew for macOS dependencies.])
	dnl Allow env override but do not be fooled by 'BREW=t'.
	test t = "$BREW" && unset BREW
	AC_CHECK_PROG([BREW], [brew], [$as_dir/$ac_word$ac_exec_ext], [], [$BREW_PATH$PATH_SEPARATOR$PATH$PATH_SEPARATOR/bin$PATH_SEPARATOR/usr/bin$PATH_SEPARATOR/usr/local/bin])
	AS_IF([test "x$BREW" = "x"],[
		AC_MSG_WARN([Homebrew not found])
		BREW_FOUND=no
	], [
		BREW_FOUND=yes

		AC_MSG_CHECKING([for openssl availability within Brew])
		AS_IF([! $BREW --prefix --installed openssl 2>/dev/null], [
			AC_MSG_RESULT([no])

			AC_MSG_CHECKING([for openssl@1.1 availability within Brew])
			AS_IF([! $BREW --prefix --installed openssl@1.1 2>/dev/null], [
				AC_MSG_RESULT([no])

				AC_MSG_CHECKING([for openssl@3 availability within Brew])
				AS_IF([! $BREW --prefix --installed openssl@3 2>/dev/null], [
					AC_MSG_RESULT([no])
				], [
					dnl AC_MSG_RESULT([yes])
					CFLAGS="-Wno-deprecated-declarations -I$($BREW --prefix openssl@3)/include"
					CXXFLAGS="-Wno-deprecated-declarations -I$($BREW --prefix openssl@3)/include"
					CPPFLAGS="-Wno-deprecated-declarations -I$($BREW --prefix openssl@3)/include"
					LDFLAGS="-L$($BREW --prefix openssl@3)/lib"
				])
			], [
				dnl AC_MSG_RESULT([yes])
				CFLAGS="-I$($BREW --prefix openssl@1.1)/include"
				CXXFLAGS="-I$($BREW --prefix openssl@1.1)/include"
				CPPFLAGS="-I$($BREW --prefix openssl@1.1)/include"
				LDFLAGS="-L$($BREW --prefix openssl@1.1)/lib"
			])
		], [
			dnl AC_MSG_RESULT([yes])
			CFLAGS="-Wno-deprecated-declarations -I$($BREW --prefix openssl)/include"
			CXXFLAGS="-Wno-deprecated-declarations -I$($BREW --prefix openssl)/include"
			CPPFLAGS="-Wno-deprecated-declarations -I$($BREW --prefix openssl)/include"
			LDFLAGS="-L$($BREW --prefix openssl)/lib"
		])
	])

        AC_CHECK_FILE(/usr/local/Homebrew, [ CPPFLAGS="$CPPFLAGS -I/usr/local/include" ])

        dnl MacPorts
        AC_CHECK_FILE(/opt/local/include, [
            CPPFLAGS="$CPPFLAGS -I/opt/local/include -I../.."
            OSX_ALT_FLAGS=true
            AC_CHECK_FILE(/opt/local/lib, [
                LDFLAGS="$LDFLAGS -L/opt/local/lib"
            ], [
                AC_MSG_ERROR([MacPorts installation seems broken, have includes but no libs.])
            ])
        ])

        dnl XCode
        case $with_xcode in
            yes | "")
                AC_CHECK_FILE(/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift-migrator/sdk/MacOSX.sdk/usr/include, [
                    CPPFLAGS="$CPPFLAGS -I/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift-migrator/sdk/MacOSX.sdk/usr/include/ -D_XCODE -I../.."
                    OSX_ALT_FLAGS=true
                ])
                ;;
        esac
        ;;
esac
])
