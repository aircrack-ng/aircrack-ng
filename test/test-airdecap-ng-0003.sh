#!/bin/sh

set -ef

"${abs_builddir}/../airdecap-ng${EXEEXT}" \
    -e test \
    -p biscotte \
    "${abs_srcdir}/wpa.cap" \
    -o /dev/null \
    -c /dev/null | \
        ${GREP} "decrypted WPA" | \
            ${GREP} 2

exit 0

