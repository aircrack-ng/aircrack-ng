#!/bin/sh

if test ! -z "${CI}"; then exit 77; fi

# Check root
if [ $(id -u) -ne 0 ]; then
	echo "Not root, skipping"
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

# Check if there is only one radio
if [ $("${top_builddir}/scripts/airmon-ng" | egrep hwsim | wc -l) -gt 1 ]; then
	echo "More than one radio, hwsim may be in use by something else, skipping"
	exit 77
fi

# Check if interface is present and grab it
WI_IFACE=$("${top_builddir}/scripts/airmon-ng" 2>/dev/null | egrep hwsim | awk '{print $2}')
if [ -z "${WI_IFACE}" ]; then
	[ ${LOAD_MODULE} -eq 1 ] && rmmod mac80211_hwsim 2>&1 >/dev/null
	return 1
fi

# Put interface in monitor so tcpdump captures in the correct mode
ip link set ${WI_IFACE} down
iw dev ${WI_IFACE} set monitor none
ip link set ${WI_IFACE} up

# Check it is in monitor mode
if [ -z "$(iw dev ${WI_IFACE} info | egrep 'type monitor')" ]; then
	[ ${LOAD_MODULE} -eq 1 ] && rmmod mac80211_hwsim 2>&1 >/dev/null
	return 1
fi

# Start capture in the background
TEMP_PCAP=$(mktemp)
tcpdump -i ${WI_IFACE} -w ${TEMP_PCAP} -U & 2>&1 >/dev/null
# Get tcpdump PID
TCPDUMP_PID=$!

# Next test is directed
AP_MAC="00:11:22:33:44:55"
"${top_builddir}/src/aireplay-ng${EXEEXT}" \
	-0 1 \
	-a ${AP_MAC} \
	-D \
	${WI_IFACE} \
		2>&1 >/dev/null

# Wait a second so data can be written to file
# Without it, it does not have time to write it and file is empty
sleep 1

# Kill tcpdump and remove hwsim module
kill -9 ${TCPDUMP_PID}
[ ${LOAD_MODULE} -eq 1 ] && rmmod mac80211_hwsim 2>&1 >/dev/null

# There should be exactly 256 deauth
AMOUNT_PACKETS=$(tcpdump -r ${TEMP_PCAP} 2>/dev/null | grep "DeAuthentication (${AP_MAC}" | wc -l)
rm ${TEMP_PCAP}
[ ${AMOUNT_PACKETS} -eq 256 ] && exit 0

exit 1
