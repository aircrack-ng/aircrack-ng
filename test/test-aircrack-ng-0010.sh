#!/bin/sh

set -ef
#./aircrack-ng -X  -K ./test.ivs

if test ! -z "${CI}"; then exit 77; fi

"${abs_builddir}/../aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -X -K \
    "${abs_srcdir}/test.ivs" \
    -l /dev/null | \
        ${GREP} "KEY FOUND" | ${GREP} "AE:5B:7F:3A:03:D0:AF:9B:F6:8D:A5:E2:C7"

exit 0

