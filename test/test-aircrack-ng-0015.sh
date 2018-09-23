#!/bin/sh

set -ef

# if test ! -z "${CI}"; then exit 77; fi
#echo "staytogether" | ./src/aircrack-ng -e "Stay Alfred" ./test/test.hccpx -w -
echo "staytogether" | "${top_builddir}/src/aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -e "Stay Alfred" \
    -w - \
    "${abs_srcdir}/test.hccpx" \
    -l /dev/null | \
        grep "KEY FOUND"

exit 0

