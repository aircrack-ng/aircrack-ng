#!/bin/sh
# Aireplay-ng/Airodump-ng: Fake auth on shared WEP key

if test ! -z "${CI}"; then exit 77; fi

# Check root
if [ $(id -u) -ne 0 ]; then
	echo "Not root, skipping"
	exit 77
fi

# Check hostapd is present
hash hostapd 2>&1 >/dev/null
if [ $? -ne 0 ]; then
	echo "HostAPd is not installed, skipping"
	exit 77
fi

# Check wpa_supplicant is present
hash wpa_supplicant 2>&1 >/dev/null
if [ $? -ne 0 ]; then
        echo "wpa_supplicant is not installed, skipping"
        exit 77
fi

hash iw 2>&1 >/dev/null
if [ $? -ne 0 ]; then
	echo "iw is not installed, skipping"
	exit 77
fi

hash lsusb 2>&1 >/dev/null
if [ $? -ne 0 ]; then
	echo "lsusb is not installed, skipping"
	exit 77
fi

# Load module
LOAD_MODULE=0
if [ $(lsmod | egrep mac80211_hwsim | wc -l) -eq 0 ]; then
	LOAD_MODULE=1
	modprobe mac80211_hwsim radios=3 2>&1 >/dev/null
	if [ $? -ne 0 ]; then
		# XXX: It can fail if inside a container too
		echo "Failed inserting module, skipping"
		exit 77
	fi
fi

# Check there are two radios
AMOUNT_RADIOS=$("${abs_builddir}/../scripts/airmon-ng" | egrep hwsim | wc -l)
if [ ${AMOUNT_RADIOS} -ne 3 ]; then
	echo "Expected three radios, got ${AMOUNT_RADIOS}, hwsim may be in use by something else, skipping"
	exit 77
fi

# Check if interfaces are present and grab them
WI_IFACE=$("${abs_builddir}/../scripts/airmon-ng" 2>/dev/null | egrep hwsim | head -n 1 | awk '{print $2}')
WI_IFACE2=$("${abs_builddir}/../scripts/airmon-ng" 2>/dev/null | egrep hwsim | head -n 2 | tail -n 1 | awk '{print $2}')
WI_IFACE3=$("${abs_builddir}/../scripts/airmon-ng" 2>/dev/null | egrep hwsim | tail -n 1 | awk '{print $2}')
if [ -z "${WI_IFACE}" ] || [ -z "${WI_IFACE2}" ] || [ -z "${WI_IFACE3}" ]; then
	echo "Failed getting interfaces names"
	[ ${LOAD_MODULE} -eq 1 ] && rmmod mac80211_hwsim 2>&1 >/dev/null
	exit 1
fi

# Set-up hostapd
SSID=thisrocks
CHANNEL=1
TEMP_HOSTAPD_CONF=$(mktemp)
WEP_KEY="abcde"
cat <<EOF > ${TEMP_HOSTAPD_CONF} 
auth_algs=2
ssid=${SSID}
interface=${WI_IFACE}
wep_key0="${WEP_KEY}"
channel=${CHANNEL}
driver=nl80211
# Shared wep key test
EOF

# Start it
TEMP_HOSTAPD_PID="/tmp/hostapd_pid_$(date +%s)"
hostapd -B ${TEMP_HOSTAPD_CONF} -P ${TEMP_HOSTAPD_PID} 2>&1
if test $? -ne 0; then
	echo "Failed starting HostAPd"
	echo "Running airmon-ng check kill may fix the issue"
	rm -f ${TEMP_HOSTAPD_CONF}
	[ ${LOAD_MODULE} -eq 1 ] && rmmod mac80211_hwsim 2>&1 >/dev/null
	exit 1
fi


# Put third interface in monitor mode
ip link set ${WI_IFACE3} down
iw dev ${WI_IFACE3} set monitor none
ip link set ${WI_IFACE3} up
iw dev ${WI_IFACE3} set channel ${CHANNEL}

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
AD_PID=$(ps faux | grep airodump | grep "${TEMP_FILE}" | grep -v grep | gawk '{print $2}')
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
# Shared wep key authentication
EOF

# Run wpa_supplicant
# Set interface up
ip link set ${WI_IFACE2} up
iw dev ${WI_IFACE2} set channel ${CHANNEL}


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
kill -9 $(cat ${TEMP_HOSTAPD_PID} ) 2>&1 >/dev/null
[ ${LOAD_MODULE} -eq 1 ] && rmmod mac80211_hwsim 2>&1 >/dev/null
rm -f ${TEMP_HOSTAPD_CONF} ${TEMP_FILE}*

exit ${RET}
