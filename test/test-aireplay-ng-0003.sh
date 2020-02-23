#!/bin/sh
# Aireplay-ng: directed deauth

if test ! -z "${CI}"; then exit 77; fi

# Load helper functions
. "${abs_builddir}/../test/int-test-common.sh"

# Check root
check_root

# Check all required tools are installed
check_airmon_ng_deps_present
is_tool_present tcpdump

# Check for interfering processes
airmon_ng_check

trap  cleanup INT QUIT SEGV PIPE ALRM TERM EXIT

# Load mac80211_hwsim
load_module 1

# Check there are two radios
check_radios_present 1

# Get interface name
get_hwsim_interface_name 1
WI_IFACE=${IFACE}

# Put interface in monitor so tcpdump captures in the correct mode
set_monitor_mode ${WI_IFACE}
[ $? -eq 1 ] && exit 1

# Start tcpdump capture in the background
TCPDUMP_IFACE=${WI_IFACE}
run_tcpdump

# Next test is directed
AP_MAC="00:11:22:33:44:55"
CLIENT_MAC="00:13:37:00:11:22"
"${abs_builddir}/../aireplay-ng${EXEEXT}" \
	-0 1 \
	-a ${AP_MAC} \
	-c ${CLIENT_MAC} \
	-D \
	${WI_IFACE} \
		2>&1 >/dev/null

# Wait a second
sleep 2

# Kill tcpdump
kill_tcpdump

# Count packets
AMOUNT_PACKETS_AP=$(tcpdump -r ${TEMP_TCPDUMP_PCAP} 2>/dev/null | ${GREP} "DeAuthentication (${AP_MAC}" | wc -l)
AMOUNT_PACKETS_CLIENT=$(tcpdump -r ${TEMP_TCPDUMP_PCAP} 2>/dev/null | ${GREP} "DeAuthentication (${CLIENT_MAC}" | wc -l)

# There should be exactly 256 deauth total
RET=0
if [ ${AMOUNT_PACKETS_CLIENT} -ne 128 ]; then
	RET=1
	echo "Expected 128 deauth frames from the client, got ${AMOUNT_PACKETS_CLIENT}"
fi

if [ ${AMOUNT_PACKETS_AP} -ne 128 ]; then
	RET=1
	echo "Expected 128 deauth frames from the AP, got ${AMOUNT_PACKETS_AP}"
fi

exit ${RET}
