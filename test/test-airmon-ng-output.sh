#!/bin/sh

set -eu

script=${1:-scripts/airmon-ng.linux}
tmpdir=$(mktemp -d)
trap 'rm -rf "${tmpdir}"' EXIT

awk '
	/^getFirmware\(\) \{/ { copying = 1 }
	copying { print }
	copying && /^}/ { exit }
' "${script}" > "${tmpdir}/get-firmware.sh"

# shellcheck source=/dev/null
. "${tmpdir}/get-firmware.sh"

# Read by the extracted getFirmware function.
# shellcheck disable=SC2034
DEBUG=0

assert_no_literal_tabs() {
	if printf '%s' "$1" | grep -F '\t' > /dev/null; then
		printf 'literal tab escape found in output: %s\n' "$1" >&2
		exit 1
	fi
}

render_verbose_row() {
	# Assigned by the extracted getFirmware function.
	# shellcheck disable=SC2153
	printf '%s[%s]%s%b%s[%s]-%s%b%b%s%b%b\n' \
		"${FROM}" "${PHYDEV}" "${iface}" "${FIELD1t}" "${DRIVER}" \
		"${STACK}" "${FIRMWARE}" "${FIRMWAREt-}" "${FIELD2t}" \
		"${CHIPSET}" "${CHIPSETt}" "${EXTENDED}"
}

FROM=K
PHYDEV=phy0
iface=wlan0
FIELD1t='\t\t'
DRIVER=iwlwifi
STACK=mac80211
FIELD2t='\t'
CHIPSET='Intel Corporation 700 Series Chipset CNVi WiFi (rev 11)'
CHIPSETt='\t\t\t\t'
EXTENDED='rfkill soft blocked'
ethtool_output='firmware-version: 89.735b75a4.0'

getFirmware
actual=$(render_verbose_row)
expected=$(printf 'K[phy0]wlan0\t\tiwlwifi[mac80211]-89.735b75a4.0\t\tIntel Corporation 700 Series Chipset CNVi WiFi (rev 11)\t\t\t\trfkill soft blocked')

[ "${actual}" = "${expected}" ]
assert_no_literal_tabs "${actual}"

for case in 'ath9k_htc:1.4.0' 'other:N/A' 'other:1.2.3'; do
	DRIVER=${case%%:*}
	firmware=${case#*:}
	# Read by the extracted getFirmware function.
	# shellcheck disable=SC2034
	ethtool_output="firmware-version: ${firmware}"
	unset FIRMWARE FIRMWAREt
	getFirmware
	assert_no_literal_tabs "${FIRMWARE}"
done

printf 'airmon-ng output regression test: ok\n'
