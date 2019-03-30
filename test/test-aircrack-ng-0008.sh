#!/bin/sh

set -ef

"${abs_builddir}/../aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -w "${abs_srcdir}/password.lst" \
    -a 2 \
    -e test \
    -q "${abs_srcdir}/n-02.cap" \
	"${abs_srcdir}/wep_64_ptw.cap" \
	"${abs_srcdir}/wep.open.system.authentication.cap" \
	"${abs_srcdir}/wep.shared.key.authentication.cap" \
	"${abs_srcdir}/wpa2.eapol.cap" \
	"${abs_srcdir}/wpa2-psk-linksys.cap" \
	"${abs_srcdir}/wpa.cap" \
	"${abs_srcdir}/wpa-psk-linksys.cap" \
	"${abs_srcdir}/Chinese-SSID-Name.pcap" \
	"${abs_srcdir}/wpaclean_crash.pcap" \
	"${abs_srcdir}/wps2.0.pcap" | \
        ${GREP} 'KEY FOUND! \[ biscotte \]'

exit 0

