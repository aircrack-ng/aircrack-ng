#! /bin/sh
#
# Carlos Alberto Lopez Perez <clopez@igalia.com>
#
TESTDIR="$(dirname $0)"
tmpfile="$(mktemp -u -t acng.XXXX)"
# Clean on exit
trap "rm -fr "${tmpdir}"" SIGINT SIGKILL SIGQUIT SIGSEGV SIGPIPE SIGALRM SIGTERM EXIT

echo Harkonen | ./airolib-ng "${tmpfile}" --import essid -
[ $? -ne 0 ] && exit 1

./airolib-ng "${tmpfile}" --import passwd "${TESTDIR}/password.lst"
[ $? -ne 0 ] && exit 1

./airolib-ng "${tmpfile}" --batch | grep "Computed 233 PMK"
[ $? -ne 0 ] && exit 1

./aircrack-ng -q -e Harkonen  -r "${tmpfile}"  "${TESTDIR}/wpa2.eapol.cap" | grep 'KEY FOUND! \[ 12345678 \]'
[ $? -ne 0 ] && exit 1

exit 0
