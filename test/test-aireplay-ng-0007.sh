#!/bin/sh
# Aireplay-ng/Airodump-ng: Fake auth on shared WEP key

if test ! -z "${CI}"; then exit 77; fi

# Load helper functions
. "${abs_builddir}/../test/int-test-common.sh"

# Check root
check_root

# Check all required tools are installed
check_airmon_ng_deps_present
is_tool_present screen
is_tool_present hostapd
is_tool_present wpa_supplicant

# Check for interfering processes
airmon_ng_check

# Cleanup
finish() {
	screen_cleanup
	[ -n "${AD_PID}" ] && kill -9 ${AD_PID}
	[ -n "${TEMP_FILE}" ] && [ -f "${TEMP_FILE}-01.csv" ] && rm -f ${TEMP_FILE}-01.*
	[ -n "${XOR_FILE}" ] && [ -f "${XOR_FILE}" ] && rm -f ${XOR_FILE}
	cleanup
}

trap  finish INT QUIT SEGV PIPE ALRM TERM EXIT

# Load mac80211_hwsim
load_module 3

# Check there are two radios
check_radios_present 3

# Get interfaces names
get_hwsim_interface_name 1
WI_IFACE=${IFACE}
get_hwsim_interface_name 2
WI_IFACE2=${IFACE}
get_hwsim_interface_name 3
WI_IFACE3=${IFACE}

# Set-up hostapd
SSID=thisrocks
CHANNEL=1
TEMP_HOSTAPD_CONF_FILE=$(mktemp)
WEP_KEY="abcde"
cat <<EOF > ${TEMP_HOSTAPD_CONF_FILE} 
auth_algs=2
ssid=${SSID}
interface=${WI_IFACE}
wep_key0="${WEP_KEY}"
channel=${CHANNEL}
driver=nl80211
# Aireplay-ng test 7
EOF

# Start HostAPd
run_hostapd ${TEMP_HOSTAPD_CONF_FILE}
[ $? -eq 0 ] && exit 1

# Put third interface in monitor mode
set_monitor_mode ${WI_IFACE3}
[ $? -eq 1 ] && exit 1
set_interface_channel ${WI_IFACE3} ${CHANNEL}
[ $? -eq 1 ] && exit 1

# Run airodump-ng in the background
TEMP_FILE=$(mktemp -u)
screen -AmdS capture \
	"${abs_builddir}/../airodump-ng" \
		${WI_IFACE3} \
		-c  ${CHANNEL} \
		-w ${TEMP_FILE} \
		--background 1

# Wait 3 secs
sleep 3

# Get airodump-ng PID
AD_PID=$(ps faux | ${GREP} airodump | ${GREP} "${TEMP_FILE}" | ${GREP} -v grep | ${AWK} '{print $2}')
if [ -z "${AD_PID}" ]; then
	echo "Failed starting airodump-ng"
	exit 1
fi

# Prepare WPA Supplicant
cat >> ${TEMP_WPAS_CONF_FILE} << EOF
network={
	ssid="${SSID}"
	key_mgmt=NONE
	auth_alg=SHARED
	wep_key0="${WEP_KEY}"
	wep_tx_keyidx=0
}
# Aireplay-ng test 7
EOF

# Run wpa_supplicant
# Set interface up
set_interface_channel ${WI_IFACE2} ${CHANNEL}
[ $? -eq 1 ] && exit 1

# Start wpa_supplicant
run_wpa_supplicant ${TEMP_WPAS_CONF_FILE} ${WI_IFACE2}

# Wait for wpa_supplicant to be done
sleep 6

# Clean up
kill -9 ${AD_PID}
kill_wpa_supplicant

# Check we have the xor file
XOR_FILE="$(ls -1 ${TEMP_FILE}*.xor)"
if [ -z "${XOR_FILE}" ]; then
	echo "Failed getting XOR file from airodump-ng from real authentication"
	exit 1
fi

# Run aireplay-ng fakeauth
"${abs_builddir}/../aireplay-ng" \
	--fakeauth 0 \
	-e "${SSID}" \
	-y ${XOR_FILE} \
		${WI_IFACE3}

exit $?
