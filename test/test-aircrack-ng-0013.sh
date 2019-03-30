#!/bin/sh

set -ef

# if test ! -z "${CI}"; then exit 77; fi

"${abs_builddir}/../aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -b 28:10:7B:94:BB:29 \
    -w "${abs_srcdir}/password-3.lst" \
    -a 2 \
    "${abs_srcdir}/test1.pcap" \
    -l /dev/null -q | \
        ${GREP} "KEY FOUND" | ${GREP} "15211521"

exit 0

