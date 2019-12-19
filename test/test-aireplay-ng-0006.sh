#!/bin/sh
# Aireplay-ng: deauth test with reason code

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

# Get interfaces names
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
"${abs_builddir}/../aireplay-ng${EXEEXT}" \
	-0 1 \
	-a ${AP_MAC} \
	-D \
	--deauth-rc 10 \
	${WI_IFACE} \
		2>&1 >/dev/null

# Wait a second
sleep 2

# Kill tcpdump
kill_tcpdump

# There should be exactly 256 deauth
AMOUNT_PACKETS=$(tcpdump -r ${TEMP_TCPDUMP_PCAP} 2>/dev/null | ${GREP} "DeAuthentication (${AP_MAC}" | ${GREP} 'Disassociated because the information in the Power Capability element is unacceptable' | wc -l)
[ ${AMOUNT_PACKETS} -eq 256 ] && exit 0

echo "Expected 256 deauth frames, got ${AMOUNT_PACKETS}"

exit 1
