#!/usr/bin/env bash

set -e

./autogen.sh --with-experimental --with-gcrypt
make
make check
make clean
exit 0
