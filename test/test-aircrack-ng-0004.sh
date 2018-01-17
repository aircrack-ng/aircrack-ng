#!/bin/sh

set -ef

"${top_builddir}/src/aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -w "${abs_srcdir}/password.lst" \
    -a 2 \
    -e linksys \
    -q "${abs_srcdir}/wpa-psk-linksys.cap" | \
        grep 'KEY FOUND! \[ dictionary \]'

exit 0

