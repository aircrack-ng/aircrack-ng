#! /bin/sh
#
# Carlos Alberto Lopez Perez <clopez@igalia.com>
# Thomas d'Otreppe <tdotreppe@aircrack-ng.org> - Support for sha1 and sh
TESTDIR="$(dirname $0)"
if [ "$(uname -s)" = 'OpenBSD' ]; then
	tmpdir="$(mktemp -d -t acng.XXXXXX)"
else
	tmpdir="$(mktemp -d -t acng.XXXX)"
fi

compute_sha1() {
    if type "sha1sum" > /dev/null 2>/dev/null ; then
        sha1sum "${1}" | awk '{print $1}'
    elif type "shasum" > /dev/null 2>/dev/null ; then
        shasum "${1}" | awk '{print $1}'
    elif type "sha1" > /dev/null 2>/dev/null ; then
        sha1 -q "${1}"
    else
        echo "Unable to find something to compute sha1" 1>&2
	exit 1
    fi
}


# Clean on exit
if [ "$(uname -s)" = 'OpenBSD' ]; then
	trap "rm -rf "${tmpdir}"" EXIT
else
	trap "rm -fr "${tmpdir}"" SIGINT SIGKILL SIGQUIT SIGSEGV SIGPIPE SIGALRM SIGTERM EXIT
fi
# Test1
cp -f "${TESTDIR}/wpa.cap" "${tmpdir}"
./airdecap-ng -e test -p biscotte "${tmpdir}/wpa.cap" | \
        grep "Number of decrypted WPA  packets         2" || exit 1
[ $? -ne 0 ] && exit 1
result=$(compute_sha1 "${tmpdir}/wpa-dec.cap")

if [ "${result}" != "69f8557cf96a26060989e88adfb521a01fc9b122" ] &&
        [ "${result}" != "fb1592b2c0dccef542c1f46297394ee2892f8ed3" ]; then
        exit 1
fi

# Test 2
cp -f "${TESTDIR}/wpa-psk-linksys.cap" "${tmpdir}"
./airdecap-ng -e linksys -p dictionary "${tmpdir}/wpa-psk-linksys.cap" | \
        grep "Number of decrypted WPA  packets        53"
[ $? -ne 0 ] && exit 1
result=$(compute_sha1 "${tmpdir}/wpa-psk-linksys-dec.cap")

if [ "${result}" != "1e75a9af0d9703c4ae4fc8ea454326aeb4abecc1" ] &&
        [ "${result}"  != "1c3c4123ba6718bd3db66de251a125ed65cd6ee6" ]; then
        exit 1
fi

# Test 3
cp -f "${TESTDIR}/wpa2-psk-linksys.cap" "${tmpdir}"
./airdecap-ng -e linksys -p dictionary "${tmpdir}/wpa2-psk-linksys.cap" | \
        grep "Number of decrypted WPA  packets        25"
[ $? -ne 0 ] && exit 1
result=$(compute_sha1 "${tmpdir}/wpa2-psk-linksys-dec.cap")

if [ "${result}" != "2da107b96fbe19d926020ffb0da72553b18a5775" ] &&
        [ "${result}" != "dc7d033b9759838d57b74db04185c3586cbd8042" ]; then
        exit 1
fi
exit 0
