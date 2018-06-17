#!/usr/bin/env bash

set -e

EXTRA=
case "${CC:=}" in
    clang*|llvm*) EXTRA="--with-asan";;
esac

./autogen.sh --with-experimental --with-gcrypt ${EXTRA}
make
make check || { find test -name 'test-suite.log' -exec cat {} ';' && exit 1; }
make clean
exit 0
