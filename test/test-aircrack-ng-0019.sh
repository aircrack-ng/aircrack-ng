#!/bin/sh

set -ef

"${abs_builddir}/../aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -w "${abs_srcdir}/pass.txt" \
    "${abs_srcdir}/MOM1.cap" | \
        ${GREP} 'KEY FOUND! \[ MOM12345 \]'

exit 0

