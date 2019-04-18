#!/bin/sh
# Airbase-ng open, hidden SSID and auth with fakeauth (wrong ssid and then correct)

# Temporarily disable the test
exit 77

if test ! -z "${CI}"; then exit 77; fi

CHANNEL=1
SSID=thisrocks

# Load helper functions
. "${abs_builddir}/../test/int-test-common.sh"

# Check for buggy hwsim
check_hwsim_bug

# Check root
check_root

# Check all required tools are installed
check_airmon_ng_deps_present
is_tool_present tcpdump

# Cleanup
finish() {
	cleanup
	if [ -n "${AB_PID}" ]; then
		is_pid_running ${AB_PID}
		[ $? -eq 1 ] && kill -9 ${AB_PID}
	fi
	[ -n "${AB_TEMP}" ] && rm -f ${AB_TEMP}
}

trap finish INT QUIT SEGV PIPE ALRM TERM

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
	-X \
	-c ${CHANNEL} \
	-e "${SSID}" \
	${WI_IFACE2} \
	2>&1 >${AB_TEMP} \
	&

AB_PID=$!

sleep 1
is_pid_running ${AB_PID}
if [ $? -eq 0 ]; then
	echo "Airbase-ng process died"
	cleanup
	rm -f ${AB_TEMP}
	exit 1
fi

# Set interface in monitor mode
set_monitor_mode ${WI_IFACE}
set_interface_channel ${WI_IFACE} ${CHANNEL}

# Capture a beacon to check if it contains an SSID
BEACON="$(tcpdump -c 1 -i ${WI_IFACE} 2>/dev/null | grep Beacon)"


if [ -z "${BEACON}" ]; then
	echo "Did not receive a beacon"
	kill -9 ${AB_PID}
	rm -f ${AB_TEMP}
	cleanup
	exit 1
fi
echo "${BEACON}"

if [ $(echo "${BEACON}" | grep "Beacon (${SSID})" | wc -l) -eq 1 ]; then
	echo "SSID is not hidden"
	kill -9 ${AB_PID}
	rm -f ${AB_TEMP}
	cleanup
	exit 1
fi

# Start aireplay-ng fakeauth with wrong ssid
"${abs_builddir}/../aireplay-ng${EXEEXT}" \
	--fakeauth 0 \
	--essid "${SSID}asdf" \
	${WI_IFACE}

if [ $? -eq 1 ]; then
	# Should have failed
	echo "Fakeauth succeeded when it should have failed"
	kill -9 ${AB_PID}
	rm -f ${AB_TEMP}
	cleanup
	exit 1
fi

# Start aireplay-ng fakeauth with correct ssid
"${abs_builddir}/../aireplay-ng${EXEEXT}" \
	--fakeauth 0 \
	--essid "${SSID}asdf" \
	${WI_IFACE}

if [ $? -eq 0 ]; then
	echo "Fakeauth failed"
	kill -9 ${AB_PID}
	rm -f ${AB_TEMP}
	cleanup
	exit 1
fi

# wait another 2 secs then kill airbase-ng
sleep 2
kill -9 ${AB_PID}

# Check Airbase-ng output
AB_PCAP="$(${GREP} 'Created capture file' ${AB_TEMP} | ${AWK} -F\" '{print $2}')"
CLIENT_CONNECT=$(${GREP} Client ${AB_TEMP} | ${GREP} ${ENCRYPT} | wc -l)

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
        ${GREP} "KEY FOUND! \[ ${PSK} \]"

RET=$?

# Display message in case of failure
[ ${RET} -eq 1 ] && echo "Failed cracking passphrase"

exit ${RET}
