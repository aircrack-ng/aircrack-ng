#!/bin/sh

set -ef

"${abs_builddir}/../aircrack-ng${EXEEXT}" \
	-w "${abs_srcdir}/password.lst" \
	"${abs_srcdir}/wpa2.eapol.cap" \
	-a 2 \
	-N $(mktemp -u) \
	-e Harkonen \
	-q | \
		${GREP} 'KEY FOUND! \[ 12345678 \]'

exit 0

