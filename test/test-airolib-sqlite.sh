#! /bin/sh
#
# Carlos Alberto Lopez Perez <clopez@igalia.com>
#
TESTDIR="$(dirname $0)"
tmpfile="$(mktemp -u -t acng.XXXX)"
# Clean on exit
trap "rm -fr "${tmpdir}"" INT QUIT SEGV PIPE ALRM TERM EXIT

echo Harkonen | "${top_builddir}/src/airolib-ng${EXEEXT}" "${tmpfile}" --import essid -
[ $? -ne 0 ] && exit 1

"${top_builddir}/src/airolib-ng${EXEEXT}" "${tmpfile}" --import passwd "${TESTDIR}/password.lst"
[ $? -ne 0 ] && exit 1

"${top_builddir}/src/airolib-ng${EXEEXT}" "${tmpfile}" --batch | grep "Computed 233 PMK"
[ $? -ne 0 ] && exit 1

"${top_builddir}/src//aircrack-ng${EXEEXT}" -q -e Harkonen  -r "${tmpfile}"  "${TESTDIR}/wpa2.eapol.cap" | grep 'KEY FOUND! \[ 12345678 \]'
[ $? -ne 0 ] && exit 1

exit 0
