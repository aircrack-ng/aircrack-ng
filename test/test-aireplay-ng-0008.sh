#!/bin/sh
# Aireplay-ng/Airodump-ng: Fake auth on a 5GHz channel 

if test ! -z "${CI}"; then exit 77; fi

# Load helper functions
. "${abs_builddir}/../test/int-test-common.sh"

# Check root
check_root

# Check all required tools are installed
check_airmon_ng_deps_present
is_tool_present screen
is_tool_present hostapd

# Check for interfering processes
airmon_ng_check

trap  cleanup INT QUIT SEGV PIPE ALRM TERM EXIT

# Load mac80211_hwsim
load_module 2

# Check there are two radios
check_radios_present 2

# Get interfaces names
get_hwsim_interface_name 1
WI_IFACE=${IFACE}
get_hwsim_interface_name 2
WI_IFACE2=${IFACE}

# Check if 5GHz is allowed
get_first_5ghz_channel ${WI_IFACE}
if [ $? -eq 1 ]; then
	backup_regdomain
	set_regdomain US
fi
get_first_5ghz_channel ${WI_IFACE}
if [ $? -eq 1 ]; then
	echo 'Failed getting a 5GHz channel after setting a regdomain known to allow it'
	exit 1
fi

# Set-up hostapd
SSID=thisrocks
CHANNEL=${FIRST_5GHZ_CHANNEL}
TEMP_HOSTAPD_CONF_FILE=$(mktemp)
WEP_KEY="abcdf"
cat <<EOF > ${TEMP_HOSTAPD_CONF_FILE} 
auth_algs=1
ssid=${SSID}
interface=${WI_IFACE}
wep_key0="${WEP_KEY}"
channel=${CHANNEL}
hw_mode=a
driver=nl80211
# Aireplay-ng test 8
EOF

# Start HostAPd
run_hostapd ${TEMP_HOSTAPD_CONF_FILE}
[ $? -eq 0 ] && exit 1

# Put other interface in monitor mode
set_monitor_mode ${WI_IFACE2}
[ $? -eq 1 ] && exit 1

set_interface_channel ${WI_IFACE2} ${CHANNEL}
[ $? -eq 1 ] && exit 1

# Run aireplay-ng fakeauth
"${abs_builddir}/../aireplay-ng" \
	--fakeauth 0 \
	-e "${SSID}" \
		${WI_IFACE2}

exit $?
