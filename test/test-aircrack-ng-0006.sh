#!/bin/sh

set -ef

cat > session << EOF
${abs_srcdir}
00:0D:93:EB:B0:8C
0 0
4
${top_builddir}/src/aircrack-ng${EXEEXT}
${abs_srcdir}/wpa.cap
-w
${abs_srcdir}/password.lst
EOF


"${top_builddir}/src/aircrack-ng${EXEEXT}" \
    -R ${abs_srcdir}/session | \
        grep 'KEY FOUND! \[ biscotte \]'

if [ -f session ]; then
	rm session
	exit 1
fi

exit 0

