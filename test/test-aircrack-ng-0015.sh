#!/bin/sh

set -ef

echo "staytogether" | "${top_builddir}/src/aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -e "Stay Alfred" \
    -w - \
    "${abs_srcdir}/StayAlfred.hccapx" \
    -l /dev/null | \
        grep "KEY FOUND"

exit 0

