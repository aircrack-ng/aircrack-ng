#!/bin/sh

MD5_BIN="md5sum"
TMP_DEC=$(mktemp -u)
TMP_MD5=$(mktemp -u)

if type "md5" > /dev/null 2>/dev/null ; then
	MD5_BIN="md5 -q"
fi

"${abs_builddir}/../airdecap-ng${EXEEXT}" \
	"${abs_srcdir}/capture_wds-01.cap" \
	-e test1 \
	-p 12345678 \
	-b 00:11:22:00:00:00 \
	-o ${TMP_DEC} | \
		cut -b 40- | \
		 tr -d ' ' | \
		${MD5_BIN} | \
		cut -b 1-32 > ${TMP_MD5}

if [ "$(cat ${TMP_MD5})" != '45a93bc091a3929a7d63f86ddbb81401' ]; then
	#rm ${TMP_MD5} ${TMP_DEC}
	echo "Unexpected airdecap-ng output"
	echo "Decrypted file: ${TMP_DEC}"
	exit 1
fi

rm ${TMP_MD5}
if [ "$(${MD5_BIN} ${TMP_DEC} | cut -b 1-32)" != '340b5bc23bec76e88f6a2df0cd2eeb33' ]; then
	echo "Unexpected decrypted file: ${TMP_DEC}"
	exit 1
fi

rm ${TMP_DEC}


exit 0

