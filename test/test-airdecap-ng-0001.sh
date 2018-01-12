#!/bin/sh

set -ef

"${top_builddir}/src/airdecap-ng${EXEEXT}" \
    -e linksys \
    -p dictionary \
    "${abs_srcdir}/wpa2-psk-linksys.cap" \
    -o /dev/null \
    -c /dev/null | \
        grep "decrypted WPA" | \
            grep 25

exit 0

