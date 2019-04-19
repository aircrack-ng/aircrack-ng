#!/bin/sh
# Airbase-ng open, hidden SSID and auth with fakeauth (wrong ssid and then correct)

# Temporarily disable the test
exit 77

if test ! -z "${CI}"; then exit 77; fi

CHANNEL=1
SSID=thisrocks

# Load helper functions
. "${abs_builddir}/../test/int-test-common.sh"

# Check root
check_root

# Check all required tools are installed
check_airmon_ng_deps_present
is_tool_present tcpdump

# Check for interfering processes
airmon_ng_check

# Cleanup
finish() {
	if [ -n "${AB_PID}" ]; then
		is_pid_running ${AB_PID}
		[ $? -eq 1 ] && kill -9 ${AB_PID}
	fi
	[ -n "${AB_TEMP}" ] && rm -f ${AB_TEMP}
	cleanup
}

trap finish INT QUIT SEGV PIPE ALRM TERM EXIT

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
	exit 1
fi

# Get airbase-ng PCAP
AB_PCAP="$(${GREP} 'Created capture file' ${AB_TEMP} | ${AWK} -F\" '{print $2}')"

# Set interface in monitor mode
set_monitor_mode ${WI_IFACE}
[ $? -eq 1 ] && exit 1
set_interface_channel ${WI_IFACE} ${CHANNEL}
[ $? -eq 1 ] && exit 1

# Capture a beacon to check if it contains an SSID
BEACON="$(tcpdump -c 1 -i ${WI_IFACE} 2>/dev/null | grep Beacon)"


if [ -z "${BEACON}" ]; then
	echo "Did not receive a beacon"
	exit 1
fi
echo "${BEACON}"

if [ $(echo "${BEACON}" | grep "Beacon (${SSID})" | wc -l) -eq 1 ]; then
	echo "SSID is not hidden"
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
	exit 1
fi

# Start aireplay-ng fakeauth with correct ssid
"${abs_builddir}/../aireplay-ng${EXEEXT}" \
	--fakeauth 0 \
	--essid "${SSID}asdf" \
	${WI_IFACE}

if [ $? -eq 0 ]; then
	echo "Fakeauth failed"
	exit 1
fi

# wait another 2 secs for packets to be written
sleep 2

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

# Display message in case of failure
[ ${RET} -eq 1 ] && echo "Failed cracking passphrase"

exit ${RET}
