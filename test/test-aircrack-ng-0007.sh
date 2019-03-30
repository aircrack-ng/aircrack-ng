#!/bin/sh

set -ef

"${abs_builddir}/../aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -w "${abs_srcdir}/password-2.lst" \
    -a 3 \
    -e Neheb \
    -q "${abs_srcdir}/n-02.cap" | \
        ${GREP} 'KEY FOUND! \[ bo$$password \]' || \
            echo 'SKIP: CMAC may be missing.'

exit 0

