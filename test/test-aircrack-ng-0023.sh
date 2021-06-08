#!/bin/sh

set -ef

"${abs_builddir}/../aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -w "${abs_srcdir}/password.lst" \
    -a 2 \
    -e WLAN-2 \
    -q "${abs_srcdir}/testm1m2m3.pcap" | \
        ${GREP} 'KEY FOUND! \[ 12345678 \]'

exit 0

