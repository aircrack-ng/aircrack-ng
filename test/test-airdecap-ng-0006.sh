#!/bin/sh
# BSSID changing

TMP_OUTPUT=$(mktemp -u)

"${abs_builddir}/../airdecap-ng${EXEEXT}" \
	"${abs_srcdir}/zn2i.pcap" \
	-e dlink \
	-p 12345678 \
	-o /dev/null > ${TMP_OUTPUT}

if [ "$(grep 'Number of decrypted WPA' ${TMP_OUTPUT} |  awk '{print $6}')" != '1' ]; then
	echo "Failed decrypting"
	exit 1
fi

exit 0

