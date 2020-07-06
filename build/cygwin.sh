#!/usr/bin/env bash

set -euf

COMPILER=gcc

if [ $# -gt 0 ]
then
	COMPILER="${1}"
	shift
fi

echo "I: ${COMPILER} compiler"

if [ "x${COMPILER}" = xclang ]
then
	# shellcheck disable=SC2012
	CC=$(ls -vl /usr/bin/clang{,-{0..9}*} 2>/dev/null | awk '{ gsub("/usr/bin/",""); print $9 }' | tail -n 1)
	# shellcheck disable=SC2012
	CXX=$(ls -vl /usr/bin/clang++{,-{0..9}*} 2>/dev/null | awk '{ gsub("/usr/bin/",""); print $9 }' | tail -n 1)
	LIBS='-liconv'

	export CC CXX LIBS
fi

CPUS=$(($(grep -c processor /proc/cpuinfo) * 3 / 2))
CFLAGS="-Os -g -DNDEBUG"
CXXFLAGS="-Os -g -DNDEBUG"
export CFLAGS CXXFLAGS
PATH="/usr/lib/ccache:$PATH"
export PATH

if [ -e /usr/bin/ccache ]
then
	CC="ccache ${CC:=gcc}"
	CXX="ccache ${CXX:=g++}"
	export CC CXX
fi

RETRY=0

while [ $RETRY -lt 3 ];
do
	autoreconf -vi && ./configure "$@" && break
	[ -f config.log ] && cat config.log

	echo "W: failed to run autogen.sh, will retry..."
	RETRY=$((RETRY + 1))
	sleep $((10 * RETRY))
done

if [ $RETRY -ge 3 ];
then
	echo "F: All retries failed, aborting..."
	exit 1
fi

ccache -s || echo "W: Skip ccache stats..."
make -j ${CPUS:-1}
make check || { find . -name 'test-suite.log' -exec cat {} ';' && exit 1; }
make clean
ccache -s || echo "W: Skip ccache stats..."

exit 0
