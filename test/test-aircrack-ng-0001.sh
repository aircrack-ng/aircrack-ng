#!/bin/sh

set -ef

"${abs_builddir}/../aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -w "${abs_srcdir}/password.lst" \
    -a 2 \
    -e Harkonen \
    -q "${abs_srcdir}/wpa2.eapol.cap" | \
        ${GREP} 'KEY FOUND! \[ 12345678 \]'

exit 0

