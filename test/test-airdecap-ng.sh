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
# We receive from Makefile the path to src/ and we put it as first option on $PATH
# This allows us to run the test against the recent compiled binary if we are called
# from Makefile (make check). Otherwise we run the test against the installed binary
# on the system.
[[ -d "$1" ]] && export PATH="${1}:${PATH}"
TESTDIR="$(dirname $0)"
tmpdir="$(mktemp -d)"
# Clean on exit
trap "rm -fr "${tmpdir}"" SIGINT SIGKILL SIGQUIT SIGSEGV SIGPIPE SIGALRM SIGTERM EXIT
# Test1
cp -f "${TESTDIR}/wpa.cap" "${tmpdir}"
airdecap-ng -e test -p biscotte "${tmpdir}/wpa.cap" | tee /dev/stderr | grep -q "Number of decrypted WPA  packets         2"
# Check that the hash is what we expect
[[ $(sha1sum "${tmpdir}/wpa-dec.cap" | awk '{print $1}') == "69f8557cf96a26060989e88adfb521a01fc9b122" ]]
# Test 2
cp -f "${TESTDIR}/wpa-psk-linksys.cap" "${tmpdir}"
airdecap-ng -e linksys -p dictionary "${tmpdir}/wpa-psk-linksys.cap" | tee /dev/stderr | grep -q "Number of decrypted WPA  packets        53"
[[ $(sha1sum "${tmpdir}/wpa-psk-linksys-dec.cap" | awk '{print $1}') == "1e75a9af0d9703c4ae4fc8ea454326aeb4abecc1" ]]
# Test 3
cp -f "${TESTDIR}/wpa2-psk-linksys.cap" "${tmpdir}"
airdecap-ng -e linksys -p dictionary "${tmpdir}/wpa2-psk-linksys.cap" | tee /dev/stderr | grep -q "Number of decrypted WPA  packets        25"
[[ $(sha1sum "${tmpdir}/wpa2-psk-linksys-dec.cap" | awk '{print $1}') == "2da107b96fbe19d926020ffb0da72553b18a5775" ]]
