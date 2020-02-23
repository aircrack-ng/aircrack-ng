#!/bin/sh

cleanup() {
	echo "Cleanup"
	kill_wpa_supplicant
	kill_hostapd
	# takes care of killing tcpdump if necessary
	clean_tcpdump
	unload_module
	restore_regdomain
}

screen_cleanup() {
	SCREEN_NAME=capture
	[ -n "$1" ] && SCREEN_NAME="$1"
	screen -S ${SCREEN_NAME} -p 0 -X quit
	screen -wipe
}

check_arg_is_number() {
	if [ -z "$1" ]; then
		echo "${2}() requires an argument, and it must be a number"
		exit 1
	fi
	if [ -z "$(echo $1 | ${GREP} -E '^[0-9]{1,}$')" ]; then
		echo "${2}() expects the a number, got $1"
		exit 1
	fi
}

MODULE_LOADED=0
load_module() {
	check_arg_is_number "$1" 'load_module'

	if [ -z "$(lsmod | ${GREP} mac80211_hwsim)" ]; then
		echo "Loading mac80211_hwsim with $1 radios"
		modprobe mac80211_hwsim radios=$1 2>&1 >/dev/null
		if [ $? -ne 0 ]; then
			# XXX: It can fail if inside a container too
			echo "Failed inserting module, skipping"
			exit 1
		fi
		MODULE_LOADED=1
	else
		echo 'mac80211_hwsim already loaded, unload it first!'
		exit 1
	fi
}

check_radios_present() {
	check_arg_is_number "$1" 'check_radios_present'

	AMOUNT_RADIOS=$("${abs_builddir}/../scripts/airmon-ng" | ${GREP} hwsim | wc -l)
	if [ ${AMOUNT_RADIOS} -ne $1 ]; then
		echo "Expected $1 radios, got ${AMOUNT_RADIOS}, hwsim may be in use by something else, aborting"
		exit 1
	fi

	echo "Correct amount of radios present: $1"
}

airmon_ng_check() {
	# Display output of "airmon-ng check" if there are interfering process
	# Can help in detecting if previous tests didn't clean up
	# Or, if running the first test, check if there are interfering processes
	if [ $("${abs_builddir}/../scripts/airmon-ng" check | grep "PID" | wc -l) -eq 1 ]; then
		"${abs_builddir}/../scripts/airmon-ng" check
	fi
}

unload_module() {
	if [ ${MODULE_LOADED} -eq 1 ]; then
		echo 'Unloading mac80211_hwsim'
		rmmod mac80211_hwsim 2>/dev/null >/dev/null
	fi
}

is_pid_running() {
	check_arg_is_number "$1" 'is_pid_running'

	[ ! -f "/proc/${1}/status" ] && return 0

	return 1
}

check_tools_compiled() {
	echo 'Checking required Aircrack-ng tools are compiled'

	# Check that all the tools are compiled
	if [ ! -f "${abs_builddir}/../scripts/airmon-ng" ]; then
		echo 'Tools are unlikely to be compiled - airmon-ng is not present'
		exit 1
	fi

	# Linux only, we'll have to adapt if we ever support Windows officially
	if [ ! -f "${abs_builddir}/../aircrack-ng" ] \
		|| [ ! -f "${abs_builddir}/../aircrack-ng" ] \
		|| [ ! -f "${abs_builddir}/../airodump-ng" ] \
		|| [ ! -f "${abs_builddir}/../aireplay-ng" ]; then
		echo 'Aircrack-ng tools not compiled'
		exit 1
	fi
}

check_root() {
	if [ $(id -u) -ne 0 ]; then
		echo 'Not root, skipping'
		exit 77
	fi

	echo 'User is root'
}

is_tool_present() {
	if [ -z "$1" ]; then
		echo 'is_tool_present() requires the name of the tool'
		exit 1
	fi

	hash $1 2>&1 >/dev/null
	if [ $? -ne 0 ]; then
		echo "$1 is not installed, aborting!"
		exit 1
	fi
	echo "$1 is present"
}

check_airmon_ng_deps_present() {
	is_tool_present iw
	is_tool_present lsusb
}

get_hwsim_interface_name() {
	check_arg_is_number "$1" 'get_hwsim_interface_name'

	IFACE=$("${abs_builddir}/../scripts/airmon-ng" 2>/dev/null | ${GREP} hwsim | head -n $1 | tail -n 1 | ${AWK} '{print $2}')

	if [ -z "${IFACE}" ]; then
		echo "Failed getting interface $1"
		cleanup
		exit 1
	fi
	echo "Interface $1 name: ${IFACE}"
}

######################## regdomain iw commands ########################

REG_DOMAIN=""

backup_regdomain() {
	REG_DOMAIN="$(iw reg get | ${GREP} country | ${AWK} -F\: '{print $1}' | ${AWK} '{print $2}')"
	echo "Current regdomain: ${REG_DOMAIN}"
}

set_regdomain() {
	if [ -z "$1" ]; then
		echo "set_regdomain(): No regdomain given"
		retun 1
	fi

	echo "Changing regdomain to $1"
	iw reg set $1
}

restore_regdomain() {
	[ -n "${REG_DOMAIN}" ] && set_regdomain ${REG_DOMAIN}
}

########################## Channel settings ##########################

FIRST_5GHZ_CHANNEL=""

get_first_5ghz_channel() {
	if [ -z "$1" ]; then
		echo 'get_first_5ghz_channel(): missing interface name'
		return 1
	fi

	TMP_IFACE_PHY=$(iw dev $1 info | ${GREP} wiphy | ${AWK} '{print $2}')

	if [ -z "${TMP_IFACE_PHY}" ]; then
		echo "get_first_5ghz_channel(): Interface $1 does not exist or does not have associated PHY"
		return 1
	fi

	FIRST_5GHZ_CHANNEL=$(iw phy phy${TMP_IFACE_PHY} info | ${GREP} -E '\* 5[0-9]{3} MHz' | ${GREP} -v -E '(no IR|disabled)' | ${AWK} -F\[ '{ print $2}' | ${AWK} -F\] '{print $1}' | head -n 1)

	if [ -z "${FIRST_5GHZ_CHANNEL}" ]; then
		echo "get_first_5ghz_channel(): No 5GHz channel available"
		return 1
	fi

	if [ $(echo "${FIRST_5GHZ_CHANNEL}" | ${GREP} -E '^[1-9][0-9]{1,2}$' | wc -l) -ne 1 ]; then
		echo "get_first_5ghz_channel(): Failure to get channel: ${FIRST_5GHZ_CHANNEL}"
		return 1
	fi
	echo "First 5GHz channel: ${FIRST_5GHZ_CHANNEL}"

	return 0
}

set_interface_channel() {
	if [ -z "$1" ]; then
		echo 'set_monitor_mode(): missing interface name'
		return 1
	fi

	check_arg_is_number "$2" 'set_interface_channel'

	echo "Setting $1 on channel $2"
	ip link set $1 up
	iw dev $1 set channel $2
	if [ $? -eq 1 ]; then
		echo "iw dev $1 set channel $2 failed, exiting"
		return 1
	fi
	return 0
}

set_monitor_mode() {
	if [ -z "$1" ]; then
		echo 'set_monitor_mode(): missing interface name'
		return 1
	fi

	echo "Putting $1 in monitor mode"
	ip link set $1 down
	iw dev $1 set monitor none
	if [ $? -eq 1 ]; then
		echo "iw dev $1 set monitor none failed, exiting"
		return 1
	fi
	ip link set $1 up

	# Check card is in monitor mode
	IFACE_MODE=$(iw dev $1 info | grep type | awk '{print $2}')
	if [ "${IFACE_MODE}" != 'monitor' ]; then
		echo "Failed to set $1 in monitor mode: ${IFACE_MODE}"
		return 1
	fi

	return 0
}

########################## tcpdump ##########################

TCPDUMP_PID=""
TEMP_TCPDUMP_PCAP=$(mktemp -u)
TCPDUMP_IFACE=""
run_tcpdump() {
	ADDL_TCPDUMP_PARAMS="$1"

	if [ -z "{TCPDUMP_IFACE}" ]; then
		echo 'Missing capture interface'
		cleanup
		exit 1
	fi

	if [ -n "$1" ]; then
		echo "Additional tcpdump parameters: $1"
		cleanup
		exit 1
	fi

	# Run tcpdump
	echo "Starting tcpdump on ${TCPDUMP_IFACE}"
	tcpdump -Z root -i ${TCPDUMP_IFACE} -w ${TEMP_TCPDUMP_PCAP} -U ${ADDL_TCPDUMP_PARAMS} & 2>&1 >/dev/null

	# Get PID
	TCPDUMP_PID=$!
	sleep 1
	is_pid_running ${TCPDUMP_PID}
	if [ $? -eq 0 ]; then
		echo 'Failed starting tcpdump'
		cleanup
		return 0
	fi

	# Display PID
	echo "tcpdump PID: ${TCPDUMP_PID}"

	return 1
}

kill_tcpdump() {
	if [ -n "${TCPDUMP_PID}" ] && [ -f "/proc/${TCPDUMP_PID}/status" ]; then

		echo "Killing tcpdump PID ${TCPDUMP_PID}"

		# If there is nothing, just kill it slowly
		if [ -z "$1" ]; then
			# Kill tcpdump (SIGTERM)
			kill -15 ${TCPDUMP_PID}

			# Wait a few seconds so it exits gracefully and
			# writes the frames to the file
			sleep 3
		fi

		# Kill and cleanup
		kill -9 ${TCPDUMP_PID} 2>/dev/null
		TCPDUMP_PID=""
	fi
}

clean_tcpdump() {
	kill_tcpdump nowait

	if [ -n "${TEMP_TCPDUMP_PCAP}" ] && [ -f ${TEMP_TCPDUMP_PCAP} ]; then
		rm -f ${TEMP_TCPDUMP_PCAP}
		TEMP_TCPDUMP_PCAP=""
	fi
}

########################## HostAPd ##########################

HOSTAPD_PID_FILE=$(mktemp -u)

# PID is more of a convenience
HOSTAPD_PID=""
TEMP_HOSTAPD_CONF_FILE=$(mktemp -u)
run_hostapd() {
	# Check configuration file is present
	if [ -z "$1" ]; then
		echo 'HostAPd requires a configuration file'
		cleanup
		exit 1
	fi

	if [ ! -f "$1" ]; then
		echo "HostAPd configuration file $1 does not exist"
		cleanup
		exit 1
	fi

	TEMP_HOSTAPD_CONF_FILE="$1"

	# Run HostAPd
	echo "Starting HostAPd with ${TEMP_HOSTAPD_CONF_FILE}"
	hostapd -P ${HOSTAPD_PID_FILE} -B ${TEMP_HOSTAPD_CONF_FILE} 2>&1
	if test $? -ne 0; then
		echo 'Failed starting HostAPd with the following configuration:'
		cat ${TEMP_HOSTAPD_CONF_FILE}
		echo '------------'
		echo 'Running airmon-ng check kill may fix the issue'
		cleanup
		return 0
	fi

	# Get PID
	sleep 0.5
	HOSTAPD_PID=$(cat ${HOSTAPD_PID_FILE} 2>/dev/null)
	echo "HostAPd PID: ${HOSTAPD_PID}"

	return 1
}

kill_hostapd() {
	if [ -n "${TEMP_HOSTAPD_CONF_FILE}" ] && [ -f ${HOSTAPD_PID_FILE} ]; then

		# Get HostAPd PID
		PID_TO_KILL=$(cat ${HOSTAPD_PID_FILE} 2>/dev/null)
		echo "Killing HostAPd PID ${PID_TO_KILL}"

		# Kill and cleanup
		kill -9 ${PID_TO_KILL}
		rm -f ${TEMP_HOSTAPD_CONF_FILE} ${HOSTAPD_PID_FILE}
		TEMP_HOSTAPD_CONF_FILE=""
		HOSTAPD_PID=""
		HOSTAPD_PID_FILE=""
	fi
}

########################## WPA supplicant ##########################

WPAS_PID_FILE=$(mktemp -u)

# PID is more of a convenience
WPAS_PID=""
TEMP_WPAS_CONF_FILE=$(mktemp -u)
run_wpa_supplicant() {
	# Check configuration file is present
	if [ -z "$1" ] || [ -z "$2" ]; then
		echo 'WPA_supplicant requires a configuration file and a wifi interface'
		cleanup
		exit 1
	fi

	if [ ! -f "$1" ]; then
		echo "WPA_supplicant configuration file $1 does not exist"
		cleanup
		exit 1
	fi

	TEMP_WPAS_CONF_FILE="$1"

	# Run WPA supplicant
	echo "Starting WPA_supplicant with ${TEMP_WPAS_CONF_FILE} on $2"
	wpa_supplicant -B -Dnl80211 -i $2 -c ${TEMP_WPAS_CONF_FILE} -P ${WPAS_PID_FILE} 2>&1
	if test $? -ne 0; then
		echo 'Failed starting WPA supplicant with the following configuration:'
		cat ${TEMP_WPAS_CONF_FILE}
		echo '------------'
		echo 'Running airmon-ng check kill may fix the issue'
		cleanup
		exit 1
	fi

	# Get PID
	sleep 0.5
	WPAS_PID=$(cat ${WPAS_PID_FILE} 2>/dev/null)
	echo "WPA supplicant PID: ${WPAS_PID}"
}

kill_wpa_supplicant() {
	if [ -n "${TEMP_WPAS_CONF_FILE}" ] && [ -f ${WPAS_PID_FILE} ]; then

		# Get WPA supplicant PID
		PID_TO_KILL=$(cat ${WPAS_PID_FILE} 2>/dev/null)
		echo "Killing WPA supplicant PID ${PID_TO_KILL}"

		# Kill and cleanup
		kill -9 ${PID_TO_KILL}
		rm -f ${TEMP_WPAS_CONF_FILE} ${WPAS_PID_FILE}
		TEMP_WPAS_CONF_FILE=""
		WPAS_PID=""
		WPAS_PID_FILE=""
	fi
}

check_tools_compiled