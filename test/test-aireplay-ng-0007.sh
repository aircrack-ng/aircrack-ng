#!/bin/sh
# Aireplay-ng/Airodump-ng: Fake auth on shared WEP key

if test ! -z "${CI}"; then exit 77; fi

# Load helper functions
. "${abs_builddir}/../test/int-test-common.sh"

# Check root
check_root

# Check all required tools are installed
check_airmon_ng_deps_present
is_tool_present hostapd
is_tool_present wpa_supplicant

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
set_interface_channel ${WI_IFACE3} ${CHANNEL}

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
	kill -9 $(cat ${TEMP_HOSTAPD_PID}) ${AD_PID}
	rm -rf ${TEMP_HOSTAPD_CONF} ${TEMP_WPAS_CONF}
	[ ${LOAD_MODULE} -eq 1 ] && rmmod mac80211_hwsim 2>&1 >/dev/null
	exit 1
fi

# Prepare WPA Supplicant
TEMP_WPAS_CONF=$(mktemp)
cat >> ${TEMP_WPAS_CONF} << EOF
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

# Start wpa_supplicant
WPAS_PID=$(mktemp -u)
wpa_supplicant -B -Dnl80211 -i ${WI_IFACE2} -c ${TEMP_WPAS_CONF} -P ${WPAS_PID} 2>&1
if test $? -ne 0; then
	echo "Failed starting wpa_supplicant"
	echo "Running airmon-ng check kill may fix the issue"
	kill -9 $(cat ${TEMP_HOSTAPD_PID}) ${AD_PID}
	rm -rf ${TEMP_HOSTAPD_CONF} ${TEMP_WPAS_CONF}
	kill -9 ${AD_PID}
	[ ${LOAD_MODULE} -eq 1 ] && rmmod mac80211_hwsim 2>&1 >/dev/null
	exit 1
fi

# Wait for wpa_supplicant to be done
sleep 6

# Clean up
kill -9 ${AD_PID} $(cat ${WPAS_PID})
rm -f ${TEMP_WPAS_CONF} ${WPAS_PID}

# Check we have the xor file
XOR_FILE="$(ls -1 ${TEMP_FILE}*.xor)"
if [ -z "${XOR_FILE}" ]; then
	echo "Failed getting XOR file from airodump-ng from real authentication"
	kill -9 $(cat ${TEMP_HOSTAPD_PID})
	rm -f ${TEMP_HOSTAPD_CONF}
	[ ${LOAD_MODULE} -eq 1 ] && rmmod mac80211_hwsim 2>&1 >/dev/null
	exit 1
fi

# Run aireplay-ng fakeauth
"${abs_builddir}/../aireplay-ng" \
	--fakeauth 0 \
	-e "${SSID}" \
	-y ${XOR_FILE} \
		${WI_IFACE3}

RET=$?

# Some cleanup
cleanup
rm -f ${TEMP_FILE}*

exit ${RET}
