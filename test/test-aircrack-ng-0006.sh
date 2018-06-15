#!/bin/sh

set -ef

echo "asciipsk" > ${abs_srcdir}/1word

cat > ${abs_srcdir}/session << EOF
${abs_srcdir}
00:0D:93:EB:B0:8C
1 0 0
4
${top_builddir}/src/aircrack-ng${EXEEXT}
${abs_srcdir}/wpa.cap
-w
${abs_srcdir}/1word,${abs_srcdir}/password.lst
EOF

"${top_builddir}/src/aircrack-ng${EXEEXT}" \
    -R ${abs_srcdir}/session | \
        grep 'KEY FOUND! \[ biscotte \]'

rm -f ${abs_srcdir}/1word

if [ -f ${abs_srcdir}/session ]; then
	rm ${abs_srcdir}/session
	exit 1
fi

exit 0

