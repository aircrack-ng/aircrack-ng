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

AC_DEFUN([AIRCRACK_NG_PCAP], [
AC_ARG_WITH(libpcap-include,
    [AS_HELP_STRING([--with-libpcap-include=DIR],
        [use PCAP includes in DIR, [default=auto]])
    ],[
    	if test -d "$withval" ; then
    		CPPFLAGS="$CPPFLAGS -I $withval"
    	fi
    ])

AC_ARG_WITH(libpcap-lib,
    [AS_HELP_STRING([--with-libpcap-lib=DIR],
        [use PCAP libraries in DIR, [default=auto]])
    ],[
    	if test -d "$withval" ; then
    		LDFLAGS="$LDFLAGS -L $withval"
    	fi
    ])

dnl
dnl Search for headers
dnl
if test "${with_libpcap_includes+set}" != set; then
	AC_MSG_CHECKING(pcap header directories)

	found_pcap_dir=""
	for pcap_dir in /usr/include/pcap /usr/local/include/pcap \
					$prefix/include ; do
		if test -d "$pcap_dir" ; then
			found_pcap_dir="$pcap_dir"
			break
		fi
	done

	if test "$found_pcap_dir" != "" ; then
		PCAP_CFLAGS="-I$found_pcap_dir"
		AC_SUBST([PCAP_CFLAGS])

		AC_MSG_RESULT([$found_pcap_dir])
	else
		AC_MSG_RESULT([not found])
	fi
fi

dnl
dnl Verify that required headers are useable
dnl
save_cflags="$CFLAGS"
CFLAGS="$PCAP_INCLUDES $CFLAGS"
AC_CHECK_HEADERS([pcap.h], [
	PCAP_FOUND=yes
], [
	PCAP_FOUND=no
])
CFLAGS="$saved_cflags"

dnl
dnl Locate the library
dnl
AS_IF([test "$PCAP_FOUND" = yes], [
	AC_CHECK_LIB([pcap], [pcap_open_live], [
	    PCAP_LIBS=-lpcap
	    AC_DEFINE([HAVE_PCAP], [1])
	    AC_SUBST(PCAP_LIBS)

	    PCAP_FOUND=yes
	],[ PCAP_FOUND=no ])
])

AM_CONDITIONAL([HAVE_PCAP], [test "$PCAP_FOUND" = yes])
])
