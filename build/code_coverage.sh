#!/usr/bin/env bash

set -eufx

#
# Bail on OS X for testing this functionality.
#
if [ "$TRAVIS_OS_NAME" == "osx" ]; then
    exit 0
fi

#
# Only works with GCC.
#
case "$CC" in
    clang*|llvm*) exit 0;;
esac

find . -name .deps -o -name '*.la' -o -name .libs -o -name Makefile -print0 | xargs -0 rm -vfr

autoreconf -vi
env CFLAGS="-O0 -g3" CXXFLAGS="-O0 -g3" \
    ./configure --enable-shared --with-experimental --enable-code-coverage
make clean
make
make check

lcov --compat-libtool --directory . --capture --rc lcov_branch_coverage=1 --output-file coverage.info

lcov --remove coverage.info '/tmp/*' '/usr/include/*' '/usr/local/include/*' '/usr/lib/gcc/*' '/usr/local/lib/gcc/*' --rc lcov_branch_coverage=1 -o `pwd`/coverage_filtered.info

cpp-coveralls -n -l coverage_filtered.info

exit 0
