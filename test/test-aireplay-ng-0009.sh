#!/bin/sh
# Aireplay-ng: CSA beacon injection

if test ! -z "${CI}"; then exit 77; fi

# Load helper functions
. "${abs_builddir}/../test/int-test-common.sh"

# Check root
check_root

# Check all required tools are installed
check_airmon_ng_deps_present
is_tool_present hostapd
is_tool_present tcpdump

# Check for interfering processes
airmon_ng_check

# Cleanup
finish() {
	[ -n "${OUTPUT_TEMP}" ] && rm -f ${OUTPUT_TEMP}
	cleanup
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

# Set-up hostapd
SSID=thisrocks
CHANNEL=1
TEMP_HOSTAPD_CONF_FILE=$(mktemp)
cat <<EOF > ${TEMP_HOSTAPD_CONF_FILE}
driver=nl80211
interface=${WI_IFACE}
channel=${CHANNEL}
hw_mode=g
ssid=${SSID}
# Aireplay-ng test 9
EOF

# Start HostAPd
run_hostapd ${TEMP_HOSTAPD_CONF_FILE}
[ $? -eq 0 ] && exit 1

# Put other interface in monitor mode
set_monitor_mode ${WI_IFACE2}
[ $? -eq 1 ] && exit 1
set_interface_channel ${WI_IFACE2} ${CHANNEL}
[ $? -eq 1 ] && exit 1

# Start tcpdump capture in the background
TCPDUMP_IFACE=${WI_IFACE2}
run_tcpdump

# Run actual test
OUTPUT_TEMP=$(mktemp)
"${abs_builddir}/../aireplay-ng${EXEEXT}" \
	--csa 1 \
	--csa-channel 14 \
	-e "${SSID}" \
	${WI_IFACE2} \
	> ${OUTPUT_TEMP} 2>&1

# Wait a second
sleep 2

# Kill tcpdump
kill_tcpdump

CSA_PATTERN=2503010e00
# One burst submits 64 frames; same-interface monitor capture sees each
# injection and its transmitted copy, for 128 observations.
#"type mgt subtype beacon and wlan addr3 ${AP_MAC}" - add AP_MAC lookup
AMOUNT_PACKETS=$(tcpdump -r ${TEMP_TCPDUMP_PCAP} -x "type mgt subtype beacon" 2>/dev/null | tr -d '[:space:]' | ${GREP} -o "${CSA_PATTERN}" | wc -l)

# There should be exactly 128 csa total
RET=0
if [ "${AMOUNT_PACKETS:-0}" -ne 128 ]; then
	RET=1
	echo "Expected 128 csa beacon observations, got ${AMOUNT_PACKETS}"
fi

# A zero count runs continuously; SIGINT should stop cleanly between frames.
"${abs_builddir}/../aireplay-ng${EXEEXT}" \
	--csa 0 \
	--csa-channel 14 \
	-e "${SSID}" \
	${WI_IFACE2} \
	> ${OUTPUT_TEMP} 2>&1 &
CSA_PID=$!
sleep 1
kill -INT "${CSA_PID}"
wait "${CSA_PID}"
CSA_STATUS=$?
if [ ${CSA_STATUS} -ne 0 ]; then
	RET=1
	echo "CSA attack did not stop cleanly after SIGINT"
fi

exit ${RET}
