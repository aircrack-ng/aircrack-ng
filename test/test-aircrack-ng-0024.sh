#!/bin/sh

set -ef

"${abs_builddir}/../aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -w "${abs_srcdir}/password.lst" \
    "${abs_srcdir}/pmkid-not-recognized.cap" 2>&1 | \
        ${GREP} -F "8C:DE:F9:D0:B4:61" | \
            ${GREP} -vF "PMKID" # Do NOT want to see a Enterprise PMKID here

exit 0

