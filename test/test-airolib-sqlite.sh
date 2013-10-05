#! /bin/bash
#
# Carlos Alberto Lopez Perez <clopez@igalia.com>
#
# This will fail ("set -e" + "set -o pipefail") if any error happens.
# So:
#    If this exits with zero the test is correct. Otherwise the test failed
#
set -e
set -o pipefail
TESTDIR="$(dirname $0)"
tmpfile="$(mktemp -u)"
# Clean on exit
trap "rm -f "${tmpfile}"" SIGINT SIGKILL SIGQUIT SIGSEGV SIGPIPE SIGALRM SIGTERM EXIT
echo Harkonen | ./airolib-ng "${tmpfile}" --import essid -
./airolib-ng "${tmpfile}" --import passwd "${TESTDIR}/password.lst"
./airolib-ng "${tmpfile}" --batch | grep "Computed 233 PMK"
./aircrack-ng -q -e Harkonen  -r "${tmpfile}"  "${TESTDIR}/wpa2.eapol.cap" | grep 'KEY FOUND! \[ 12345678 \]'
