#!/bin/sh

set -ef

echo 1 | "${top_builddir}/src/aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -w "${abs_srcdir}/password.lst" \
	"${abs_srcdir}/wpa2.eapol.cap" \
	"${abs_srcdir}/wps2.0.pcap" | \
	grep 'KEY FOUND! \[ 12345678 \]'

exit 0

