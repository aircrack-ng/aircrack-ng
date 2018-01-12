#!/bin/sh

set -ef

"${top_builddir}/src/aircrack-ng${EXEEXT}" \
    -w "${abs_srcdir}/password.lst" \
    -a 2 \
    -e Harkonen \
    -q "${abs_srcdir}/wpa2.eapol.cap" | \
        grep 'KEY FOUND! \[ 12345678 \]'

exit 0

