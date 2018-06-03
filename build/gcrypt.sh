#!/usr/bin/env bash

set -e

./autogen.sh --with-experimental --with-gcrypt
make
make check || { cat test/test-suite.log && exit 1; }
make clean
exit 0
