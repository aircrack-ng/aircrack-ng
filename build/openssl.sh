#!/usr/bin/env bash

set -e

EXTRA=
case "${CC:=}" in
    clang*|llvm*) export CXX=clang++;;
    *) export CFLAGS="-Werror -Wno-unused-result"; export CXXFLAGS="-Werror -Wno-unused-result";;
esac

if [ "$TRAVIS_OS_NAME" == "osx" ]; then ./autogen.sh --with-experimental ${EXTRA}; else ./autogen.sh --with-experimental ${EXTRA}; fi || { cat config.log; exit 1; }
make
make check || { find . -name 'test-suite.log' -exec cat {} ';' && exit 1; }
make clean
exit 0
