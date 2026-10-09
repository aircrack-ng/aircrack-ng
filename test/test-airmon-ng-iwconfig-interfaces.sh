#!/bin/sh

set -eu

source_file=${1:-scripts/airmon-ng.linux}
expected='wlan1
phy1.mon
wlan0'

if ! grep -F "sed -n 's/^\([^[:space:]][^[:space:]]*\)[[:space:]].*/\1/p'" \
	"${source_file}" > /dev/null; then
	printf 'missing expected iwconfig interface parser\n' >&2
	exit 1
fi

actual=$(
	printf '%s\n' \
		'wlan1     IEEE 802.11  ESSID:"test"' \
		'phy1.mon  IEEE 802.11  Mode:Monitor  Tx-Power=3 dBm' \
		'          Mode:Monitor  Frequency:2.437 GHz' \
		'          Tx-Power=3 dBm' \
		'wlan0     IEEE 802.11  ESSID:"other"' \
		| sed -n 's/^\([^[:space:]][^[:space:]]*\)[[:space:]].*/\1/p'
)

if [ "${actual}" != "${expected}" ]; then
	printf 'unexpected interface list:\n%s\n' "${actual}" >&2
	exit 1
fi

printf 'airmon-ng iwconfig interface parsing: ok\n'
