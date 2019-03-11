#!/bin/sh
# Airodump-ng: Check base files generated are good

#!/bin/sh

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
if [ $("${top_builddir}/scripts/airmon-ng" | egrep hwsim | wc -l) -ne 1 ]; then
        echo "Expected two radios but got a different amount, hwsim may be in use by something else, skipping"
        exit 77
fi

# Check if interfaces are present and grab them
WI_IFACE=$("${top_builddir}/scripts/airmon-ng" 2>/dev/null | egrep hwsim | awk '{print $2}')
if [ -z "${WI_IFACE}" ]; then
	echo "Failed getting interface name"
	[ ${LOAD_MODULE} -eq 1 ] && rmmod mac80211_hwsim 2>&1 >/dev/null
	exit 1
fi

CHANNEL=9
# Put other interface in monitor mode
ip link set ${WI_IFACE} down
iw dev ${WI_IFACE} set monitor none
ip link set ${WI_IFACE} up
iw dev ${WI_IFACE} set channel ${CHANNEL}

TEMP_FILE=$(mktemp -u)
screen -AmdS capture \
	timeout 3 \
		"${top_builddir}/src/airodump-ng" \
			${WI_IFACE} \
			-c  10 \
			-w ${TEMP_FILE} \
			--background 1

# Wait a few seconds for it to finish
sleep 5

# Unload module
[ ${LOAD_MODULE} -eq 1 ] && rmmod mac80211_hwsim 2>&1 >/dev/null

# Basic checks
if [ $(ls -1 ${TEMP_FILE}-01.* | wc -l) -ne 5 ]; then
	echo "Failed creating files"
	exit 1
fi

if [ $(md5sum "${TEMP_FILE}-01.cap" | gawk '{print $1}' ) != '50d6b6d03c0e582a1ae60986e5f53832' ]; then
	echo "Invalid PCAP file"
	rm -f ${TEMP_FILE}-01.*
	exit 1
fi

if [ $(md5sum "${TEMP_FILE}-01.csv" | gawk '{print $1}') != '7b5b92716e839e310d8edda8ec21a469' ]; then
	echo "Invalid CSV file"
	rm -f ${TEMP_FILE}-01.*
	exit 1
fi

if [ $(md5sum "${TEMP_FILE}-01.kismet.csv" | gawk '{print $1}') != '0f402e05f06f582a7931420075485369' ]; then
	echo "Invalid Kismet CSV file"
	rm -f ${TEMP_FILE}-01.*
	exit 1
fi

if [ $(md5sum "${TEMP_FILE}-01.log.csv" | gawk '{print $1}') != '6bdaf36ee12b14b2a5a80c3af8ae7160' ]; then
	echo "Invalid Log CSV"
	rm -f ${TEMP_FILE}-01.*
	exit 1
fi

# TODO: Verify Kismet NetXML
echo 'Kismet NetXML is not verified'

# Cleanup
rm -f ${TEMP_FILE}-01.*

exit 0
