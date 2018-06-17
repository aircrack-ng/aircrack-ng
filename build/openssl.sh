#!/usr/bin/env bash

set -e

EXTRA=
case "${CC:=}" in
    clang*|llvm*) EXTRA="--with-asan";;
esac

if [ "$TRAVIS_OS_NAME" == "osx" ]; then ./autogen.sh --with-experimental --with-openssl=/usr/local/Cellar/openssl/1.0.2l ${EXTRA}; else ./autogen.sh --with-experimental ${EXTRA}; fi
make
make check || { find test -name 'test-suite.log' -exec cat {} ';' && exit 1; }
make clean
exit 0
