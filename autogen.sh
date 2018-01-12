#!/bin/sh
#
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
# exception to your dnl version of the file(s), but you are not obligated
# to do so.
#
# If you dnl do not wish to do so, delete this exception statement from your
# version.
#
# If you delete this exception statement from all source files in the
# program, then also delete it here.

set -euf

test -n "${srcdir:-}" || srcdir="$(dirname "$0")"
test -n "${srcdir:-}" || srcdir=.

olddir="$(pwd)"
cd "$srcdir"

missing_tool()
{
	_prog="$1"
	_env="$2"

	echo "Could not auto-detect '${_prog}'; please install or specify the '${_env}' environment variable."
	exit 1
}


if [ -z "${LIBTOOLIZE:-}" ]; then
	if which libtoolize >/dev/null 2>/dev/null; then
		LIBTOOLIZE="$(which libtoolize 2>/dev/null)"
	elif which glibtoolize >/dev/null 2>/dev/null; then
		LIBTOOLIZE="$(which glibtoolize 2>/dev/null)"
	else
		missing_tool libtoolize LIBTOOLIZE
	fi
fi

if [ -z "${ACLOCAL:-}" ]; then
	if which aclocal >/dev/null 2>/dev/null; then
		ACLOCAL="$(which aclocal 2>/dev/null)"
	else
		missing_tool aclocal ACLOCAL
	fi
fi

if [ -z "${AUTOCONF:-}" ]; then
	if which autoconf >/dev/null 2>/dev/null; then
		AUTOCONF="$(which autoconf 2>/dev/null)"
	else
		missing_tool autoconf AUTOCONF
	fi
fi

if [ -z "${AUTOHEADER:-}" ]; then
	if which autoheader >/dev/null 2>/dev/null; then
		AUTOHEADER="$(which autoheader 2>/dev/null)"
	else
		missing_tool autoheader AUTOHEADER
	fi
fi

if [ -z "${AUTOMAKE:-}" ]; then
	if which automake >/dev/null 2>/dev/null; then
		AUTOMAKE="$(which automake 2>/dev/null)"
	else
		missing_tool automake AUTOMAKE
	fi
fi

"$LIBTOOLIZE" --force --copy --automake
"$ACLOCAL" -I build/m4/stubs -I build/m4 ${ACLOCAL_FLAGS:-}
"$AUTOCONF"
# "$AUTOHEADER"
"$AUTOMAKE" \
    --gnu --add-missing --force --copy \
    -Wno-portability -Wno-portability

{ cat <<EOF
#!/usr/bin/env bash
./autogen.sh "$@" "\$@"
EOF
} > reautogen.sh
chmod +x reautogen.sh

if [ ! -z "${NOCONFIGURE:-}" ]; then
    echo "Done. ./configure skipped."
    exit $?
fi

exec ./configure "$@"

