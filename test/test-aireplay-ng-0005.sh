#!/bin/sh
# Injection test with bitrate

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
AMOUNT_RADIOS=$("${top_builddir}/scripts/airmon-ng" | egrep hwsim | wc -l)
if [ ${AMOUNT_RADIOS} -ne 2 ]; then
	echo "Expected two radios, got ${AMOUNT_RADIOS}, hwsim may be in use by something else, skipping"
	exit 77
fi

# Check if interfaces are present and grab them
WI_IFACE=$("${top_builddir}/scripts/airmon-ng" 2>/dev/null | egrep hwsim | head -n 1 | awk '{print $2}')
WI_IFACE2=$("${top_builddir}/scripts/airmon-ng" 2>/dev/null | egrep hwsim | tail -n 1 | awk '{print $2}')
if [ -z "${WI_IFACE}" ] || [ -z "${WI_IFACE2}" ]; then
	echo "Failed getting interfaces names"
	[ ${LOAD_MODULE} -eq 1 ] && rmmod mac80211_hwsim 2>&1 >/dev/null
	exit 1
fi

# Set-up hostapd
SSID=thisrocks
CHANNEL=1
TEMP_HOSTAPD_CONF=$(mktemp)
cat <<EOF > ${TEMP_HOSTAPD_CONF} 
driver=nl80211
interface=${WI_IFACE}
channel=${CHANNEL}
hw_mode=g
ssid=${SSID}
# Test 5
EOF

# Start it
TEMP_HOSTAPD_PID="/tmp/hostapd_pid_$(date +%s)"
hostapd -B ${TEMP_HOSTAPD_CONF} -P ${TEMP_HOSTAPD_PID} 2>&1
if test $? -ne 0; then
	echo "Failed starting HostAPd"
	echo "Running airmon-ng check kill may fix the issue"
	[ ${LOAD_MODULE} -eq 1 ] && rmmod mac80211_hwsim 2>&1 >/dev/null
	exit 1
fi


# Put other interface in monitor mode
ip link set ${WI_IFACE2} down
iw dev ${WI_IFACE2} set monitor none
ip link set ${WI_IFACE2} up
iw dev ${WI_IFACE2} set channel ${CHANNEL}

# Run actual test
OUTPUT_TEMP=$(mktemp)
"${top_builddir}/src/aireplay-ng${EXEEXT}" \
    -9 \
    -B \
    ${WI_IFACE2} \
	2>&1 > ${OUTPUT_TEMP}

# Some cleanup
kill -9 $(cat ${TEMP_HOSTAPD_PID} ) 2>&1 >/dev/null
[ ${LOAD_MODULE} -eq 1 ] && rmmod mac80211_hwsim 2>&1 >/dev/null

# Then checks
if [ -z "$(grep 'Injection is working!' ${OUTPUT_TEMP})" ]; then
	echo "Injection is not working"
	rm -f ${OUTPUT_TEMP}
	exit 1
fi

if [ -z "$(grep '30/30' ${OUTPUT_TEMP})" ]; then
	echo "AP not present or failure injecting"
	rm -f ${OUTPUT_TEMP}
	exit 1
fi

if [ -z "$(grep 'Probing at 54.0 Mbps:	30/30: 100%' ${OUTPUT_TEMP})" ]; then
	echo "Failed bitrate test"
	rm -f ${OUTPUT_TEMP}
	exit 1
fi

rm ${OUTPUT_TEMP}

exit 0
