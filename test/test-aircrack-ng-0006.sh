#!/bin/sh

set -ef

echo "asciipsk" > 1word

cat > session << EOF
${abs_srcdir}
00:0D:93:EB:B0:8C
1 0 0
4
${top_builddir}/src/aircrack-ng${EXEEXT}
${abs_srcdir}/wpa.cap
-w
1word,${abs_srcdir}/password.lst
EOF

"${top_builddir}/src/aircrack-ng${EXEEXT}" \
    -R ${abs_srcdir}/session | \
        grep 'KEY FOUND! \[ biscotte \]'

rm -f 1word

if [ -f session ]; then
	rm session
	exit 1
fi

exit 0

