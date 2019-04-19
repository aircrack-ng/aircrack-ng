#!/bin/sh
# Airodump-ng: Check base files generated are good

if test ! -z "${CI}"; then exit 77; fi

# Load helper functions
. "${abs_builddir}/../test/int-test-common.sh"

# Check root
check_root

# Check all required tools are installed
check_airmon_ng_deps_present
is_tool_present screen

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

CHANNEL=9

# Put interface in monitor mode
set_monitor_mode ${WI_IFACE}
[ $? -eq 1 ] && exit 1
set_interface_channel ${WI_IFACE} ${CHANNEL}
[ $? -eq 1 ] && exit 1

TEMP_FILE=$(mktemp -u)
screen -AmdS capture \
	timeout 3 \
		"${abs_builddir}/../airodump-ng" \
			${WI_IFACE} \
			-c  10 \
			-w ${TEMP_FILE} \
			--background 1

# Wait a few seconds for it to finish
sleep 5

# Basic checks
if [ $(ls -1 ${TEMP_FILE}-01.* | wc -l) -ne 5 ]; then
	echo "Failed creating files"
	exit 1
fi

if [ $(md5sum "${TEMP_FILE}-01.cap" | ${AWK} '{print $1}' ) != '50d6b6d03c0e582a1ae60986e5f53832' ]; then
	echo "Invalid PCAP file"
	exit 1
fi

if [ $(md5sum "${TEMP_FILE}-01.csv" | ${AWK} '{print $1}') != '7b5b92716e839e310d8edda8ec21a469' ]; then
	echo "Invalid CSV file"
	exit 1
fi

if [ $(md5sum "${TEMP_FILE}-01.kismet.csv" | ${AWK} '{print $1}') != '0f402e05f06f582a7931420075485369' ]; then
	echo "Invalid Kismet CSV file"
	exit 1
fi

if [ $(md5sum "${TEMP_FILE}-01.log.csv" | ${AWK} '{print $1}') != '6bdaf36ee12b14b2a5a80c3af8ae7160' ]; then
	echo "Invalid Log CSV"
	exit 1
fi

# TODO: Verify Kismet NetXML
echo 'Kismet NetXML is not verified'

exit 0
