#!/bin/sh
# Airbase-ng WPA supplicant authentication

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
set_interface_channel ${WI_IFACE2} ${CHANNEL}

# Run airbase-ng in the background
AB_TEMP=$(mktemp -u)
"${abs_builddir}/../airbase-ng${EXEEXT}" \
	-W 1 \
	-z 2 \
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
	cleanup
	rm ${AB_TEMP}
	exit 1
fi

# Set-up wpa_supplicant
PSK=password
TEMP_WPAS_CONF=$(mktemp)
ENCRYPT="TKIP"
cat >> ${TEMP_WPAS_CONF_FILE} << EOF
network={
	ssid="${SSID}"
	psk="${PSK}"
	proto=WPA
	key_mgmt=WPA-PSK
	group=${ENCRYPT}
	pairwise=${ENCRYPT}
}
# Airbase-ng Test 2
EOF

# Set interface up
set_interface_channel ${WI_IFACE} ${CHANNEL}

# Start wpa_supplicant
run_wpa_supplicant ${TEMP_WPAS_CONF_FILE} ${WI_IFACE}

# Wait for authentication then kill wpa supplicant
sleep 6
kill_wpa_supplicant

# wait another 2 secs then kill airbase-ng
sleep 2
kill -9 ${AB_PID}

# Check Airbase-ng output
AB_PCAP="$(grep 'Created capture file' ${AB_TEMP} | gawk -F\" '{print $2}')"
CLIENT_CONNECT=$(grep Client ${AB_TEMP} | grep ${ENCRYPT} | wc -l)

# Some cleanup
rm -f ${AB_TEMP}
cleanup

if [ ${CLIENT_CONNECT} -eq 0 ]; then
	echo "Client failed to connect to AP - possibly incorrect encryption"
	rm -f ${AB_PCAP}
	exit 1
fi

# Crack the capture
"${abs_builddir}/../aircrack-ng${EXEEXT}" \
    ${AIRCRACK_NG_ARGS} \
    -w "${abs_srcdir}/password.lst" \
    -a 2 \
    -e "${SSID}" \
    -q \
	"${AB_PCAP}" | \
        grep "KEY FOUND! \[ ${PSK} \]"

RET=$?

[ ${RET} -eq 1 ] && echo "Failed cracking passphrase"

# Cleanup PCAP
rm -f ${AB_PCAP}

# Cleanup
exit ${RET}
