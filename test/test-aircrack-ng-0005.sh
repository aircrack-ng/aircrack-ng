#!/bin/sh

set -ef

"${top_builddir}/src/aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    "${abs_srcdir}/wep_64_ptw.cap" \
    -l /dev/null | \
        grep "KEY FOUND" | grep "1F:1F:1F:1F:1F"

exit 0

