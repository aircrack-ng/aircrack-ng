#!/bin/sh

set -ef

"${abs_builddir}/../aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -w "${abs_srcdir}/password.lst" \
    -a 2 \
    -e test \
    -q "${abs_srcdir}/wpa.cap" | \
        ${GREP} 'KEY FOUND! \[ biscotte \]'

exit 0

