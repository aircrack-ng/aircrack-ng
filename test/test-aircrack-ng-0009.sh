#!/bin/sh

set -ef

echo 1 | "${abs_builddir}/../aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -w "${abs_srcdir}/password.lst" \
	"${abs_srcdir}/wpa2.eapol.cap" \
	"${abs_srcdir}/wps2.0.pcap" | \
	${GREP} 'KEY FOUND! \[ 12345678 \]'

exit 0

