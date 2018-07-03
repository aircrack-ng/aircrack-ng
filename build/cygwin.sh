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
	CC=clang-5.0
	CXX=clang++-5.0
	LIBS='-liconv'

	export CC CXX LIBS
fi

RETRY=0

while [ $RETRY -lt 3 ];
do
	./autogen.sh "$@" && break

	echo "W: failed to run autogen.sh, will retry..."
	RETRY=$(($RETRY + 1))
	sleep $((10 * $RETRY))
done

if [ $RETRY -ge 3 ];
then
	echo "F: All retries failed, aborting..."
	exit 1
fi

make
make check || { find test -name 'test-suite.log' -exec cat {} ';' && exit 1; }
make clean

exit 0
