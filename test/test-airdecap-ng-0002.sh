#!/bin/sh

set -ef

"${abs_builddir}/../airdecap-ng${EXEEXT}" \
    -e linksys \
    -p dictionary \
    "${abs_srcdir}/wpa-psk-linksys.cap" \
    -o /dev/null \
    -c /dev/null | \
        ${GREP} "decrypted WPA" | \
            ${GREP} 53

exit 0

