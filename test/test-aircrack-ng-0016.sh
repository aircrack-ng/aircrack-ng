#!/bin/sh

set -ef

# Turn our pcap into a hccapx
"${top_builddir}/src/aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -j "test" \
    -e "linksys" \
    "${abs_srcdir}/wpa2-psk-linksys.cap"

# Make sure we can load it and solve it
echo "dictionary" | "${top_builddir}/src/aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -e "linksys" \
    -w - \
    "test.hccapx" \
    -l /dev/null | \
        grep "KEY FOUND"

rm -f test.hccapx

exit 0

