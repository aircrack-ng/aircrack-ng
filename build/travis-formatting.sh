#!/bin/sh

# check formatting matches clang-format-3.8. Since newer versions can have
# changes in formatting even without any rule changes, we have to fix on a
# single version.
. ./build/clang_format_all.sh

git clean -f

# Print any diff here, so the error message below is the last thing
git diff

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
