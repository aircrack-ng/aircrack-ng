#!/usr/bin/env bash

set -e

EXTRA=
case "${CC:=}" in
    clang*|llvm*) export CXX=clang++;;
    *) export CFLAGS="-Werror -Wno-unused-result"; export CXXFLAGS="-Werror -Wno-unused-result";;
esac

./autogen.sh --with-experimental --with-gcrypt ${EXTRA} || { cat config.log; exit 1; }
make
make check || { find . -name 'test-suite.log' -exec cat {} ';' && exit 1; }
make clean
exit 0
