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
elif [ "${ID}" = 'fedora' ]; then
    echo "[*] Detected Fedora (${VERSION_ID})"
    if [ "${STEP}" = 'builder' ]; then
        dnf install -y libtool pkgconfig sqlite-devel autoconf automake openssl-devel libpcap-devel \
                        pcre2-devel rfkill libnl3-devel gcc gcc-c++ ethtool hwloc-devel libcmocka-devel \
                        make file expect hostapd wpa_supplicant iw usbutils tcpdump screen zlib-devel \
                        expect python3-pip python3-setuptools git
    elif [ "${STEP}" = 'stage2' ]; then
        dnf install -y libnl3 openssl-libs zlib libpcap sqlite-libs pcre2 hwloc iw ethtool pciutils \
                        usbutils expect python3 python3-graphviz iw util-linux ethtool kmod
    fi
elif [ "${ID}" = 'opensuse-leap' ]; then
    echo "[*] Detected openSUSE Leap"
    if [ "${STEP}" = 'builder' ]; then
        zypper install -y autoconf automake libtool pkg-config libnl3-devel libopenssl-1_1-devel zlib-devel \
                        libpcap-devel sqlite3-devel pcre2-devel hwloc-devel libcmocka-devel hostapd screen \
                        wpa_supplicant tcpdump iw gcc-c++ gcc ethtool pciutils usbutils expect python3-pip \
                        python3-setuptools git
    elif [ "${STEP}" = 'stage2' ]; then
        zypper install -y libnl3-200 libopenssl1_1 zlib libpcap sqlite3 libpcre2-8-0 hwloc iw ethtool pciutils \
                        usbutils expect python3 python3-graphviz iw util-linux ethtool kmod
    fi
else
    echo "[!] Unsupported distro: ${ID} - PR welcome"
    exit 1
fi

exit 0