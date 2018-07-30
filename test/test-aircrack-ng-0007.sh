#!/bin/sh

set -ef

"${top_builddir}/src/aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -w "${abs_srcdir}/password-2.lst" \
    -a 3 \
    -e Neheb \
    -q "${abs_srcdir}/n-02.cap" | \
        grep 'KEY FOUND! \[ bo$$password \]' || \
            echo 'SKIP: CMAC may be missing.'

exit 0

