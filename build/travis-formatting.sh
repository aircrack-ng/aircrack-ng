#!/bin/sh

#
# Bail on OS X for testing this functionality.
#
if [ "x${TRAVIS_OS_NAME:-}" = "xosx" ]; then
    exit 0
fi

#
# Only works with GCC.
#
case "$CC" in
    clang*|llvm*) exit 0;;
esac

sudo add-apt-repository -y 'deb http://apt.llvm.org/precise/ llvm-toolchain-precise-3.8 main'
wget -O - http://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
sudo apt-get update -qq
sudo apt-get install --allow-unauthenticated -y -qq clang-format-3.8

# check formatting matches clang-format-3.8. Since newer versions can have
# changes in formatting even without any rule changes, we have to fix on a
# single version.
. ./build/clang_format_all.sh

git clean -f

# Print any diff here, so the error message below is the last thing
git diff

set -e

git diff --quiet || (
  echo "***************************************************";
  echo "*** The code is not clean against clang-format  ***";
  echo "*** Please run clang-format-3.8 and fix the     ***";
  echo "*** differences then rebase/squash them into    ***";
  echo "*** the relevant commits. Do not add a commit   ***";
  echo "*** for just formatting fixes. Thanks!          ***";
  echo "***************************************************";
  exit 1;
  )

exit 0
