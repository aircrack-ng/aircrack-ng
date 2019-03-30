#! /bin/sh
#
# Carlos Alberto Lopez Perez <clopez@igalia.com>
#
TESTDIR="$(dirname $0)"
if test -f /etc/alpine-release -o "$(uname -s)" = "OpenBSD"; then
    tmpfile="$(mktemp -u -t acng.XXXXXX)"
else
    tmpfile="$(mktemp -u -t acng.XXXX)"
fi
# Clean on exit
trap "rm -fr "${tmpdir}"" INT QUIT SEGV PIPE ALRM TERM EXIT

echo Harkonen | "${abs_builddir}/../airolib-ng${EXEEXT}" "${tmpfile}" --import essid -
[ $? -ne 0 ] && exit 1

"${abs_builddir}/../airolib-ng${EXEEXT}" "${tmpfile}" --import passwd "${TESTDIR}/password.lst"
[ $? -ne 0 ] && exit 1

"${abs_builddir}/../airolib-ng${EXEEXT}" "${tmpfile}" --batch | ${GREP} "Computed 233 PMK"
[ $? -ne 0 ] && exit 1

"${abs_builddir}/../aircrack-ng${EXEEXT}" -q -e Harkonen  -r "${tmpfile}"  "${TESTDIR}/wpa2.eapol.cap" | ${GREP} 'KEY FOUND! \[ 12345678 \]'
[ $? -ne 0 ] && exit 1

exit 0
