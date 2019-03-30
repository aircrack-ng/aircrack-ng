#!/bin/sh

set -ef

"${abs_builddir}/../aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -I 'c2ea9449c142e84a0479041702526532*0012bf77162d*0021e924a5e7*574c414e2d373731363938' \
    -w "${abs_srcdir}/password-3.lst" \
    -l /dev/null | \
        ${GREP} "KEY FOUND" | ${GREP} "SP-91862D361"

exit 0

