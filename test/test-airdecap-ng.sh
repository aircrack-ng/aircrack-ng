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
tmpdir="$(mktemp -d)"
# Clean on exit
trap "rm -fr "${tmpdir}"" SIGINT SIGKILL SIGQUIT SIGSEGV SIGPIPE SIGALRM SIGTERM EXIT
# Test1
cp -f "${TESTDIR}/wpa.cap" "${tmpdir}"
./airdecap-ng -e test -p biscotte "${tmpdir}/wpa.cap" | \
	grep "Number of decrypted WPA  packets         2"
# Check that the hash is what we expect.
# For each hash there are two possibilities: little or big endian
sha1sum=$(sha1sum "${tmpdir}/wpa-dec.cap" | awk '{print $1}')
[[ "${sha1sum}" == "69f8557cf96a26060989e88adfb521a01fc9b122" ]] || \
	[[ "${sha1sum}" == "fb1592b2c0dccef542c1f46297394ee2892f8ed3" ]]
# Test 2
cp -f "${TESTDIR}/wpa-psk-linksys.cap" "${tmpdir}"
./airdecap-ng -e linksys -p dictionary "${tmpdir}/wpa-psk-linksys.cap" | \
	grep "Number of decrypted WPA  packets        53"
sha1sum=$(sha1sum "${tmpdir}/wpa-psk-linksys-dec.cap" | awk '{print $1}')
[[ "${sha1sum}" == "1e75a9af0d9703c4ae4fc8ea454326aeb4abecc1" ]] || \
	[[ "${sha1sum}"  == "1c3c4123ba6718bd3db66de251a125ed65cd6ee6" ]]
# Test 3
cp -f "${TESTDIR}/wpa2-psk-linksys.cap" "${tmpdir}"
./airdecap-ng -e linksys -p dictionary "${tmpdir}/wpa2-psk-linksys.cap" | \
	grep "Number of decrypted WPA  packets        25"
sha1sum=$(sha1sum "${tmpdir}/wpa2-psk-linksys-dec.cap" | awk '{print $1}')
[[ "${sha1sum}" == "2da107b96fbe19d926020ffb0da72553b18a5775" ]] || \
	[[ "${sha1sum}" == "dc7d033b9759838d57b74db04185c3586cbd8042" ]]
