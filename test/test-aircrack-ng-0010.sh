#!/bin/sh

set -ef
#./aircrack-ng -X  -K ./test.ivs

"${top_builddir}/src/aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -K \
    "${abs_srcdir}/test.ivs" \
    -l /dev/null | \
        grep "KEY FOUND" | grep "AE:5B:7F:3A:03:D0:AF:9B:F6:8D:A5:BB:C7"

exit 0

