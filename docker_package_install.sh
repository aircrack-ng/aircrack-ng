#!/bin/sh

echo "[*] Installing packages"
STEP=$1
if [ -z "$STEP" ]; then
    echo "[!] Must specify 'builder' or 'stage2' as arguments"
    exit 1
elif [ "$STEP" = 'builder' ]; then
    echo "[*] Builder step"
elif [ "$STEP" = 'stage2' ]; then
    echo "[*] Stage2 step"
fi

# Load OS info
# shellcheck source=/dev/null
. /etc/os-release

if [ "${ID}" = 'debian' ] || [ "${ID_LIKE}" = 'debian' ]; then
    echo "[*] Detected debian or debian-type distro"
    if [ "${STEP}" = 'builder' ]; then
        apt-get update \
        && export DEBIAN_FRONTEND=noninteractive \
        && apt-get -y install --no-install-recommends \
            build-essential autoconf automake libtool pkg-config libnl-3-dev libnl-genl-3-dev libssl-dev \
            ethtool shtool rfkill zlib1g-dev libpcap-dev libsqlite3-dev libpcre2-dev libhwloc-dev \
            libcmocka-dev hostapd wpasupplicant tcpdump screen iw usbutils expect gawk bear \
            libtinfo5 python3-pip git && \
                rm -rf /var/lib/apt/lists/*
    elif [ "${STEP}" = 'stage2' ]; then
        apt-get update && \
        apt-get -y install --no-install-recommends \
            libsqlite3-0 libssl3 hwloc libpcre2-posix3 libnl-3-200 libnl-genl-3-200 iw usbutils pciutils \
            iproute2 ethtool kmod wget ieee-data python3 python3-graphviz rfkill && \
        rm -rf /var/lib/apt/lists/*
    fi
elif [ "${ID}" = 'alpine' ]; then
    echo "[*] Detected alpine"
    if [ "${STEP}" = 'builder' ]; then
        apk add --no-cache \
            gcc g++ make autoconf automake libtool libnl3-dev openssl-dev ethtool libpcap-dev cmocka-dev \
            hostapd wpa_supplicant tcpdump screen iw pkgconf util-linux sqlite-dev pcre2-dev linux-headers \
            zlib-dev pciutils usbutils expect hwloc-dev git python3 expect gawk bear py3-pip
    elif [ "${STEP}" = 'stage2' ]; then
        apk add --no-cache \
            libnl3 openssl ethtool libpcap util-linux sqlite-dev pcre2 zlib pciutils usbutils hwloc wget \
            iproute2 kmod python3 py3-graphviz urfkill iw 
    fi
else
    echo "[!] Unsupported distro - PR welcome"
    exit 1
fi

exit 0