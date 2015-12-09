#! /bin/sh
#
# Carlos Alberto Lopez Perez <clopez@igalia.com>
# Thomas d'Otreppe <tdotreppe@aircrack-ng.org> - Support for sha1 and sh
TESTDIR="$(dirname $0)"
tmpdir="$(mktemp -d)"
# Clean on exit
trap "rm -fr "${tmpdir}"" SIGINT SIGKILL SIGQUIT SIGSEGV SIGPIPE SIGALRM SIGTERM EXIT
# Test1
cp -f "${TESTDIR}/wpa.cap" "${tmpdir}"
./airdecap-ng -e test -p biscotte "${tmpdir}/wpa.cap" | \
        grep "Number of decrypted WPA  packets         2" || exit 1
[ $? -ne 0 ] && exit 1
# Check that the hash is what we expect.
# For each hash there are two possibilities: little or big endian
if ! type "sha1sum" > /dev/null 2>/dev/null ; then
        sha1sum=$(sha1 -q "${tmpdir}/wpa-dec.cap")
else
        sha1sum=$(sha1sum "${tmpdir}/wpa-dec.cap" | awk '{print $1}')
fi

if [ "${sha1sum}" != "69f8557cf96a26060989e88adfb521a01fc9b122" ] &&
        [ "${sha1sum}" != "fb1592b2c0dccef542c1f46297394ee2892f8ed3" ]; then
        exit 1
fi

# Test 2
cp -f "${TESTDIR}/wpa-psk-linksys.cap" "${tmpdir}"
./airdecap-ng -e linksys -p dictionary "${tmpdir}/wpa-psk-linksys.cap" | \
        grep "Number of decrypted WPA  packets        53"
[ $? -ne 0 ] && exit 1
if ! type "sha1sum" > /dev/null 2>/dev/null ; then
        sha1sum=$(sha1 -q "${tmpdir}/wpa-psk-linksys-dec.cap")
else
        sha1sum=$(sha1sum "${tmpdir}/wpa-psk-linksys-dec.cap" | awk '{print $1}')
fi

if [ "${sha1sum}" != "1e75a9af0d9703c4ae4fc8ea454326aeb4abecc1" ] &&
        [ "${sha1sum}"  != "1c3c4123ba6718bd3db66de251a125ed65cd6ee6" ]; then
        exit 1
fi

# Test 3
cp -f "${TESTDIR}/wpa2-psk-linksys.cap" "${tmpdir}"
./airdecap-ng -e linksys -p dictionary "${tmpdir}/wpa2-psk-linksys.cap" | \
        grep "Number of decrypted WPA  packets        25"
[ $? -ne 0 ] && exit 1
if ! type "sha1sum" > /dev/null 2>/dev/null ; then
        sha1sum=$(sha1 -q "${tmpdir}/wpa2-psk-linksys-dec.cap")
else
        sha1sum=$(sha1sum "${tmpdir}/wpa2-psk-linksys-dec.cap" | awk '{print $1}')
fi

if [ "${sha1sum}" != "2da107b96fbe19d926020ffb0da72553b18a5775" ] &&
        [ "${sha1sum}" != "dc7d033b9759838d57b74db04185c3586cbd8042" ]; then
        exit 1
fi
exit 0
