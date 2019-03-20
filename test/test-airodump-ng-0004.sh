#!/bin/sh
# Airodump-ng: Test WPA2 detection

if test ! -z "${CI}"; then exit 77; fi

# Check root
if [ $(id -u) -ne 0 ]; then
	echo "Not root, skipping"
	exit 77
fi

# Check hostapd is present
hash screen 2>&1 >/dev/null
if [ $? -ne 0 ]; then
	echo "screen is not installed, skipping"
	exit 77
fi

hash hostapd 2>&1 >/dev/null
if [ $? -ne 0 ]; then
	echo "hostapd is not installed, skipping"
	exit 77
fi

# Load module
LOAD_MODULE=0
if [ $(lsmod | egrep mac80211_hwsim | wc -l) -eq 0 ]; then
	LOAD_MODULE=1
	modprobe mac80211_hwsim radios=1 2>&1 >/dev/null
	if [ $? -ne 0 ]; then
		# XXX: It can fail if inside a container too
		echo "Failed inserting module, skipping"
		exit 77
	fi
fi

# Check there are two radios
if [ $("${abs_builddir}/../scripts/airmon-ng" | egrep hwsim | wc -l) -ne 1 ]; then
        echo "Expected two radios but got a different amount, hwsim may be in use by something else, skipping"
        exit 77
fi

# Check if interfaces are present and grab them
WI_IFACE=$("${abs_builddir}/../scripts/airmon-ng" 2>/dev/null | egrep hwsim | awk '{print $2}')
if [ -z "${WI_IFACE}" ]; then
	echo "Failed getting interface name"
	[ ${LOAD_MODULE} -eq 1 ] && rmmod mac80211_hwsim 2>&1 >/dev/null
	exit 1
fi

# Start hostapd with WPA2 CCMP
TEMP_HOSTAPD_CONF=$(mktemp -u)
cat >> ${TEMP_HOSTAPD_CONF} << EOF
interface=${WI_IFACE}
ssid=test
channel=1
wpa=2
wpa_passphrase=password
rsn_pairwise=CCMP
# Airodump-ng test 4
EOF

# Start hostapd
TEMP_HOSTAPD_PID="/tmp/hostapd_pid_$(date +%s)"
hostapd -B ${TEMP_HOSTAPD_CONF} -P ${TEMP_HOSTAPD_PID} 2>&1
if test $? -ne 0; then
        echo "Failed starting HostAPd"
        echo "Running airmon-ng check kill may fix the issue"
	rm -f ${TEMP_HOSTAPD_CONF} ${TEMP_HOSTAPD_PID}
        [ ${LOAD_MODULE} -eq 1 ] && rmmod mac80211_hwsim 2>&1 >/dev/null
        exit 1
fi

# Start hwsim0
ip link set hwsim0 up

TEMP_FILE=$(mktemp -u)
screen -AmdS capture \
	timeout 4 \
		"${abs_builddir}/../airodump-ng" \
			hwsim0 \
			-c 1 \
			-w ${TEMP_FILE} \
			--background 1

# Wait a few seconds for it to finish
sleep 6

# Some cleanup
kill -9 $(cat ${TEMP_HOSTAPD_PID})
rm -f ${TEMP_HOSTAPD_CONF} ${TEMP_HOSTAPD_PID}
[ ${LOAD_MODULE} -eq 1 ] && rmmod mac80211_hwsim 2>&1 >/dev/null

# Check CSV
ENCRYPTION_SECTION="$(head -n 3 ${TEMP_FILE}-01.csv | tail -n 1 | gawk -F, '{print $6 $7 $8}')"
if [ -z "${ENCRYPTION_SECTION}" ]; then
	echo "Something failed with airodump-ng, did not get info from CSV"
	rm -f ${TEMP_FILE}-01.*
	exit 1
elif [ "$(echo ${ENCRYPTION_SECTION} | tr -d ' ')" != 'WPA2CCMPPSK' ]; then
	echo "Encryption section is not what is expected. Got ${ENCRYPTION_SECTION}"
	rm -f ${TEMP_FILE}-01.*
	exit 1
fi

# Check NetXML
if [ ! -f ${TEMP_FILE}-01.kismet.netxml ]; then
	echo "Kismet netxml file not found"
	rm -f ${TEMP_FILE}-01.*
	exit 1
fi
ENCRYPTION_SECTION="$(grep '<encryption>WPA+PSK</encryption>' ${TEMP_FILE}-01.kismet.netxml)"
if [ -z "${ENCRYPTION_SECTION}" ] || [ -z "$(grep '<encryption>WPA+AES-CCM</encryption>' ${TEMP_FILE}-01.kismet.netxml)" ]; then
        echo "Failed to find PSK and CCMP in the kismet netxml"
	cat ${TEMP_FILE}-01.kismet.netxml
	rm -f ${TEMP_FILE}-01.*
        exit 1
fi

# Check Kismet CSV
if [ ! -f ${TEMP_FILE}-01.kismet.csv ]; then
	echo 'Kismet CSV not found'
	rm -f ${TEMP_FILE}-01.*
	exit 1
fi
ENCRYPTION_SECTION="$(tail -n 1 ${TEMP_FILE}-01.kismet.csv | gawk -F\; '{print $8}')"
if [ "x${ENCRYPTION_SECTION}" != 'xWPA2,AES-CCM' ]; then
	echo "Encryption section not found or invalid in Kismet CSV"
	echo "Expected 'WPA2,AES-CCM', got ${ENCRYPTION_SECTION}"
	rm -f ${TEMP_FILE}-01.*
	exit 1
fi

# Cleanup
rm -f ${TEMP_FILE}-01.*

exit 0
