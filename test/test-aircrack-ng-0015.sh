#!/bin/sh

set -ef

echo "staytogether" | "${abs_builddir}/../aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -e "Stay Alfred" \
    -w - \
    "${abs_srcdir}/StayAlfred.hccapx" \
    -l /dev/null | \
        ${GREP} "KEY FOUND"

exit 0

