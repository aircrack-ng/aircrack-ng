#!/usr/bin/env bash
#
# Copyright (C) 2017 Joseph Benden <joe@benden.us>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


# Params to script are:
# 1st = Short name
# 2nd = Long name
# 3rd+ = Code/Script under test

set -euf

SHORTNAME="$1"; shift
LONGNAME="$1"; shift

#
# Begin our fold
#
echo -e 'travis_fold:start:'"${SHORTNAME}"'\n\e[0K\e[33;1m'"${LONGNAME}"'\e[0m'

#
# Begin a timed block
#
if [ "$TRAVIS_OS_NAME" == "osx" ]; then
    SHA256SUM="shasum -a 256"
else
    SHA256SUM="sha256sum"
fi
START=$(python -c 'import time; print "%.9f" % time.time()' | tr -d '.')
TOKEN=$(echo "${START}" | $SHA256SUM | cut -c1-7)
echo -e "travis_time:start:${TOKEN}"


#
# Code under test is here!
#
set +e
"$@"
rc=$?
set -e

#
# End a timed block
#
END=$(python -c 'import time; print "%.9f" % time.time()' | tr -d '.')
ELAPSED=$(echo "$END - $START" | bc)
echo -e "travis_time:end:${TOKEN}:start=${START},finish=${END},duration=${ELAPSED}"

#
# End our fold
#
echo -e "travis_fold:end:${SHORTNAME}"

exit $rc
