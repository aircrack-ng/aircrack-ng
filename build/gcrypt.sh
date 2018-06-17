#!/usr/bin/env bash

set -e

EXTRA=
case "${CC:=}" in
    clang*|llvm*) EXTRA="--with-asan";;
esac

./autogen.sh --with-experimental --with-gcrypt ${EXTRA}
make
make check || { cat test/test-suite.log && exit 1; }
make clean
exit 0
