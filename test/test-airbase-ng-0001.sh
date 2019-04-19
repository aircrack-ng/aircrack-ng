#!/bin/sh
# Airbase-ng WPA2 supplicant authentication

if test ! -z "${CI}"; then exit 77; fi

CHANNEL=1
SSID=thisrocks

# Load helper functions
. "${abs_builddir}/../test/int-test-common.sh"

# Check root
check_root

# Check all required tools are installed
check_airmon_ng_deps_present
is_tool_present wpa_supplicant

# Check for interfering processes
airmon_ng_check

# Cleanup
finish() {
	cleanup
	if [ -n "${AB_PID}" ]; then
		is_pid_running ${AB_PID}
		[ $? -eq 1 ] && kill -9 ${AB_PID}
	fi
	[ -n "${AB_TEMP}" ] && rm -f ${AB_TEMP}
	[ -n "${AB_PCAP}" ] && rm -f ${AB_PCAP}
}

trap  finish INT QUIT SEGV PIPE ALRM TERM EXIT

# Load mac80211_hwsim
load_module 2

# Check there are two radios
check_radios_present 2

# Get interfaces names
get_hwsim_interface_name 1
WI_IFACE=${IFACE}
get_hwsim_interface_name 2
WI_IFACE2=${IFACE}


# Put other interface in monitor mode
set_monitor_mode ${WI_IFACE2}
[ $? -eq 1 ] && exit 1
set_interface_channel ${WI_IFACE2} ${CHANNEL}
[ $? -eq 1 ] && exit 1

# Run airbase-ng in the background
AB_TEMP=$(mktemp -u)
"${abs_builddir}/../airbase-ng${EXEEXT}" \
	-W 1 \
	-Z 4 \
	-e "${SSID}" \
	-F $(mktemp -u) \
	${WI_IFACE2} \
	2>&1 >${AB_TEMP} \
	&

AB_PID=$!

sleep 1
is_pid_running ${AB_PID}
if [ $? -eq 0 ]; then
	echo "Airbase-ng process died"
	exit 1
fi

# Grab airbase-ng pcap filename
AB_PCAP="$(${GREP} 'Created capture file' ${AB_TEMP} | ${AWK} -F\" '{print $2}')"

# Set-up wpa_supplicant
PSK=password
ENCRYPT="CCMP"
cat >> ${TEMP_WPAS_CONF_FILE} << EOF
network={
	ssid="${SSID}"
	psk="${PSK}"
	proto=RSN
	key_mgmt=WPA-PSK
	group=${ENCRYPT}
	pairwise=${ENCRYPT}
}
# Airbase-ng Test 1
EOF

# Set interface up
set_interface_channel ${WI_IFACE} ${CHANNEL}
RET=$?

# Start wpa_supplicant
run_wpa_supplicant ${TEMP_WPAS_CONF_FILE} ${WI_IFACE}
if [ $? -eq 1 ] || [ ${RET} -eq 1 ]; then
	exit 1
fi


# Wait for authentication then kill airbase-ng
sleep 8
kill -9 ${AB_PID}

# Check Airbase-ng output
CLIENT_CONNECT=$(${GREP} Client ${AB_TEMP} | ${GREP} ${ENCRYPT} | wc -l)

if [ ${CLIENT_CONNECT} -eq 0 ]; then
	echo "Client failed to connect to AP - possibly incorrect encryption"
	exit 1
fi

# Crack the capture
timeout 60 "${abs_builddir}/../aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -w "${abs_srcdir}/password.lst" \
    -a 2 \
    -e "${SSID}" \
    -q \
	"${AB_PCAP}" | \
        ${GREP} "KEY FOUND! \[ ${PSK} \]"

RET=$?

[ ${RET} -eq 1 ] && echo "Failed cracking passphrase"

# Cleanup
exit ${RET}
