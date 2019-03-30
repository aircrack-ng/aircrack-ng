#!/bin/sh

set -ef

# if test ! -z "${CI}"; then exit 77; fi

"${abs_builddir}/../aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -b 00:12:BF:77:16:2D \
    -w "${abs_srcdir}/password-3.lst" \
    -a 2 \
    "${abs_srcdir}/test-pmkid.pcap" \
    -l /dev/null -q | \
        ${GREP} "KEY FOUND" | ${GREP} "SP-91862D361"

exit 0

