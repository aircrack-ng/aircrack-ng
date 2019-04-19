#!/bin/sh
# Airodump-ng: Test WPA2 detection

if test ! -z "${CI}"; then exit 77; fi

# Load helper functions
. "${abs_builddir}/../test/int-test-common.sh"

# Check root
check_root

# Check all required tools are installed
check_airmon_ng_deps_present
is_tool_present screen
is_tool_present hostapd

# Check for interfering processes
airmon_ng_check

# Cleanup
finish() {
	screen_cleanup
	[ -n "${TEMP_FILE}" ] && [ -f "${TEMP_FILE}-01.csv" ] && rm -f ${TEMP_FILE}*
	cleanup
}

trap  finish INT QUIT SEGV PIPE ALRM TERM EXIT

# Load mac80211_hwsim
load_module 1

# Check there are two radios
check_radios_present 1

# Get interfaces names
get_hwsim_interface_name 1
WI_IFACE=${IFACE}

# Start hostapd with WPA2 CCMP
cat >> ${TEMP_HOSTAPD_CONF_FILE} << EOF
interface=${WI_IFACE}
ssid=test
channel=1
wpa=2
wpa_passphrase=password
rsn_pairwise=CCMP
# Airodump-ng test 4
EOF

# Start hostapd
run_hostapd ${TEMP_HOSTAPD_CONF_FILE}

# Start hwsim0
ip link set hwsim0 up

TEMP_FILE=$(mktemp -u)
screen -AmdS capture \
	timeout 4 \
		"${abs_builddir}/../airodump-ng" \
			hwsim0 \
			-c 1 \
			-w ${TEMP_FILE} \
			--background 1

# Wait a few seconds for it to finish
sleep 6

# Some cleanup
cleanup

# Check CSV
ENCRYPTION_SECTION="$(head -n 3 ${TEMP_FILE}-01.csv | tail -n 1 | ${AWK} -F, '{print $6 $7 $8}')"
if [ -z "${ENCRYPTION_SECTION}" ]; then
	echo "Something failed with airodump-ng, did not get info from CSV"
	rm -f ${TEMP_FILE}-01.*
	exit 1
elif [ "$(echo ${ENCRYPTION_SECTION} | tr -d ' ')" != 'WPA2CCMPPSK' ]; then
	echo "Encryption section is not what is expected. Got ${ENCRYPTION_SECTION}"
	rm -f ${TEMP_FILE}-01.*
	exit 1
fi

# Check NetXML
if [ ! -f ${TEMP_FILE}-01.kismet.netxml ]; then
	echo "Kismet netxml file not found"
	rm -f ${TEMP_FILE}-01.*
	exit 1
fi
ENCRYPTION_SECTION="$(${GREP} '<encryption>WPA+PSK</encryption>' ${TEMP_FILE}-01.kismet.netxml)"
if [ -z "${ENCRYPTION_SECTION}" ] || [ -z "$(${GREP} '<encryption>WPA+AES-CCM</encryption>' ${TEMP_FILE}-01.kismet.netxml)" ]; then
        echo "Failed to find PSK and CCMP in the kismet netxml"
	cat ${TEMP_FILE}-01.kismet.netxml
	rm -f ${TEMP_FILE}-01.*
        exit 1
fi

# Check Kismet CSV
if [ ! -f ${TEMP_FILE}-01.kismet.csv ]; then
	echo 'Kismet CSV not found'
	rm -f ${TEMP_FILE}-01.*
	exit 1
fi
ENCRYPTION_SECTION="$(tail -n 1 ${TEMP_FILE}-01.kismet.csv | ${AWK} -F\; '{print $8}')"
if [ "x${ENCRYPTION_SECTION}" != 'xWPA2,AES-CCM' ]; then
	echo "Encryption section not found or invalid in Kismet CSV"
	echo "Expected 'WPA2,AES-CCM', got ${ENCRYPTION_SECTION}"
	rm -f ${TEMP_FILE}-01.*
	exit 1
fi

# Cleanup
rm -f ${TEMP_FILE}-01.*

exit 0
