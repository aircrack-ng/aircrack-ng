#!/bin/sh

set -ef

"${abs_builddir}/../aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -w "${abs_srcdir}/password.lst" \
    -a 2 \
    -e linksys \
    -q "${abs_srcdir}/wpa2-psk-linksys.cap" | \
        grep 'KEY FOUND! \[ dictionary \]'

exit 0

