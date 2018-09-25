#!/bin/sh

set -ef
#./src/aircrack-ng -j test ./test/wpa2-psk-linksys.cap
#./src/aircrack-ng ./test.hccap -e linksys -w -


# Turn our pcap into a hccap
"${top_builddir}/src/aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -J "test" \
    -e "linksys" \
    "${abs_srcdir}/wpa2-psk-linksys.cap"

# Make sure we can load it and solve it
# NOTE: We can't load a HCCAP file. Mostly because it doesn't have a magic number
#echo "dictionary" | "${top_builddir}/src/aircrack-ng${EXEEXT}" \
#    ${AIRCRACK_NG_ARGS} \
#    -e "linksys" \
#    -w - \
#    "test.hccap" \
#    -l /dev/null | \
#        grep "KEY FOUND"

rm -f test.hccap

exit 0
