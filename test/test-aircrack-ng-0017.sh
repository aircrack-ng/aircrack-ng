#!/bin/sh

set -ef

# Turn our pcap into a hccap
"${abs_builddir}/../aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -J "test" \
    -e "linksys" \
    "${abs_srcdir}/wpa2-psk-linksys.cap"

# Make sure we can load it and solve it
# NOTE: We can't load a HCCAP file. Mostly because it doesn't have a magic number
#echo "dictionary" | "${abs_builddir}/../aircrack-ng${EXEEXT}" \
#    ${AIRCRACK_NG_ARGS} \
#    -e "linksys" \
#    -w - \
#    "test.hccap" \
#    -l /dev/null | \
#        ${GREP} "KEY FOUND"

rm -f test.hccap

exit 0
