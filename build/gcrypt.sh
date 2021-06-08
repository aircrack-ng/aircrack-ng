#!/usr/bin/env bash

set -e

EXTRA=
case "${CC:=}" in
    clang*|llvm*) export CXX=clang++;;
    *) export CFLAGS="-Werror -Wno-unused-result -Wno-incompatible-library-redeclaration"
	   export CXXFLAGS="-Werror -Wno-unused-result -Wno-incompatible-library-redeclaration";;
esac

# shellcheck disable=SC2086
./autogen.sh --with-experimental --with-gcrypt ${EXTRA} || { cat config.log; exit 1; }
make || { cat config.log; exit 1; }
make check || { find . -name 'test-suite.log' -exec cat {} ';' && exit 1; }
make clean
exit 0
