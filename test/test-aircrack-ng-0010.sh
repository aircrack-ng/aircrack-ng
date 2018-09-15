#!/bin/sh

set -ef
#./aircrack-ng -X  -K ./test.ivs

"${top_builddir}/src/aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -K \
    "${abs_srcdir}/test.ivs" \
    -l /dev/null | \
        grep "KEY FOUND" | grep "1F:1F:1F:1F:1F"

exit 0

