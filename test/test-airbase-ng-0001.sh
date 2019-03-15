#!/bin/sh
# Airbase-ng WPA/WPA2 supplicant authentication

if test ! -z "${CI}"; then exit 77; fi

CHANNEL=1
SSID=thisrocks

# Check root
if [ $(id -u) -ne 0 ]; then
	echo "Not root, skipping"
	exit 77
fi

# Check hostapd is present
hash wpa_supplicant 2>&1 >/dev/null
if [ $? -ne 0 ]; then
	echo "WPA_supplicant is not installed, skipping"
	exit 77
fi

hash iw 2>&1 >/dev/null
if [ $? -ne 0 ]; then
	echo "iw is not installed, skipping"
	exit 77
fi

# Needed for airmon-ng
hash lsusb 2>&1 >/dev/null
if [ $? -ne 0 ]; then
	echo "lsusb is not installed, skipping"
	exit 77
fi

# Load module
LOAD_MODULE=0
if [ $(lsmod | egrep mac80211_hwsim | wc -l) -eq 0 ]; then
	LOAD_MODULE=1
	modprobe mac80211_hwsim radios=2 2>&1 >/dev/null
	if [ $? -ne 0 ]; then
		# XXX: It can fail if inside a container too
		echo "Failed inserting module, skipping"
		exit 77
	fi
fi

# Check there are two radios
AMOUNT_RADIOS=$("${abs_builddir}/../scripts/airmon-ng" | egrep hwsim | wc -l)
if [ ${AMOUNT_RADIOS} -ne 2 ]; then
        echo "Expected two radios, got ${AMOUNT_RADIOS}, hwsim may be in use by something else, skipping"
        exit 77
fi

# Check if interfaces are present and grab them
WI_IFACE=$("${abs_builddir}/../scripts/airmon-ng" 2>/dev/null | egrep hwsim | head -n 1 | awk '{print $2}')
WI_IFACE2=$("${abs_builddir}/../scripts/airmon-ng" 2>/dev/null | egrep hwsim | tail -n 1 | awk '{print $2}')
if [ -z "${WI_IFACE}" ] || [ -z "${WI_IFACE2}" ]; then
	echo "Failed getting interface names"
	[ ${LOAD_MODULE} -eq 1 ] && rmmod mac80211_hwsim 2>&1 >/dev/null
	exit 1
fi

# Put second interface in monitor mode
ip link set ${WI_IFACE2} down 2>&1
iw dev ${WI_IFACE2} set monitor none 2>&1
ip link set ${WI_IFACE2} up 2>&1
iw dev ${WI_IFACE2} set channel ${CHANNEL} 2>&1

# Run airbase-ng in the background
AB_TEMP=$(mktemp -u)
"${abs_builddir}/../airbase-ng${EXEEXT}" \
	-W 1 \
	-Z 4 \
	-e "${SSID}" \
	-F $(mktemp -u) \
	${WI_IFACE2} \
	2>&1 >${AB_TEMP} \
	&

AB_PID=$!

sleep 1
if [ ! -f "/proc/${AB_PID}/status" ]; then
	echo "Airbase-ng process died"
	[ ${LOAD_MODULE} -eq 1 ] && rmmod mac80211_hwsim 2>&1 >/dev/null
	rm ${AB_TEMP}
	exit 1
fi

# Set-up wpa_supplicant
PSK=password
TEMP_WPAS_CONF=$(mktemp)
ENCRYPT="CCMP"
cat >> ${TEMP_WPAS_CONF} << EOF
network={
	ssid="${SSID}"
	psk="${PSK}"
	proto=RSN
	key_mgmt=WPA-PSK
	group=${ENCRYPT}
	pairwise=${ENCRYPT}
}
# Airbase-ng Test 1
EOF

# Set interface up
ip link set ${WI_IFACE} up
iw dev ${WI_IFACE} set channel ${CHANNEL}

# Start wpa_supplicant
TEMP_WPAS_PID="/tmp/wpas_pid_$(date +%s)"
wpa_supplicant -B -Dnl80211 -i ${WI_IFACE} -c ${TEMP_WPAS_CONF} -P ${TEMP_WPAS_PID} 2>&1
if test $? -ne 0; then
	echo "Failed starting wpa_supplicant"
	echo "Running airmon-ng check kill may fix the issue"
	[ ${LOAD_MODULE} -eq 1 ] && rmmod mac80211_hwsim 2>&1 >/dev/null
	exit 1
fi

# Wait for authentication then kill wpa supplicant
sleep 6
kill -9 $(cat ${TEMP_WPAS_PID})
rm -f ${TEMP_WPAS_PID}

# wait another 2 secs then kill airbase-ng
sleep 2
kill -9 ${AB_PID}

# Cleanup
rm -f ${TEMP_WPAS_PID} ${TEMP_WPAS_CONF}
[ ${LOAD_MODULE} -eq 1 ] && rmmod mac80211_hwsim 2>&1 >/dev/null

# Check Airbase-ng output
AB_PCAP="$(grep 'Created capture file' ${AB_TEMP} | gawk -F\" '{print $2}')"
CLIENT_CONNECT=$(grep Client ${AB_TEMP} | grep ${ENCRYPT} | wc -l)
rm -f ${AB_TEMP}

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
        grep "KEY FOUND! \[ ${PSK} \]"

RET=$?

[ ${RET} -eq 1 ] && echo "Failed cracking passphrase"

# Cleanup PCAP
rm -f ${AB_PCAP}

# Cleanup
exit ${RET}
