#!/bin/sh

set -ef

"${top_builddir}/src/aircrack-ng${EXEEXT}" \
    -w "${abs_srcdir}/password.lst" \
    -a 2 \
    -e linksys \
    -q "${abs_srcdir}/wpa2-psk-linksys.cap" | \
        grep 'KEY FOUND! \[ dictionary \]'

exit 0

