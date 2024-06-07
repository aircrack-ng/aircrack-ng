#!/bin/sh

echo "[*] Installing packages"
STEP=$1
if [ -z "${STEP}" ]; then
    echo "[!] Must specify 'builder' or 'stage2' as arguments"
    exit 1
elif [ "${STEP}" = 'builder' ]; then
    echo "[*] Builder step"
elif [ "${STEP}" = 'stage2' ]; then
    echo "[*] Stage2 step"
fi

install_hwloc() {
    CUR_PWD=$(pwd)
    cd /tmp || exit
    wget https://download.open-mpi.org/release/hwloc/v2.10/hwloc-2.10.0.tar.bz2
    tar -jxf hwloc-2.10.0.tar.bz2
    rm hwloc-2.10.0.tar.bz2
    cd hwloc-2.10.0 || exit
    ./configure
    make -j "$(nproc)"
    make install
    cd ..
    rm -rf hwloc-2.10.0
    cd "${CUR_PWD}" || exit
}

install_iw() {
    CUR_PWD=$(pwd)
    cd /tmp || exit
    wget https://mirrors.edge.kernel.org/pub/software/network/iw/iw-6.9.tar.xz
    tar -xf iw-6.9.tar.xz
    rm iw-6.9.tar.xz
    cd iw-6.9 || exit
    make
    chmod +x iw
    mv iw /usr/local/sbin
    cd ..
    rm -rf iw-6.9
    cd "${CUR_PWD}" || exit
}

install_hostapd() {
    CUR_PWD=$(pwd)
    cd /tmp || exit
    wget https://w1.fi/releases/hostapd-2.10.tar.gz
    tar -zxf hostapd-2.10.tar.gz
    rm hostapd-2.10.tar.gz
    cd hostapd-2.10/hostapd || exit 1
    cp defconfig .config
    make
    make install
    hostapd -v
    cd ../..
    rm -rf hostapd-2.10
    cd "${CUR_PWD}" || exit
}

install_cmocka() {
    CUR_PWD=$(pwd)
    cd /tmp || exit
    wget https://cmocka.org/files/1.0/cmocka-1.0.1.tar.xz
    tar -xf cmocka-1.0.1.tar.xz
    rm cmocka-1.0.1.tar.xz
    cd cmocka-1.0.1 || exit
    mkdir build
    cd build || exit
    cmake ..
    make
    make install
    # Otherwise tests will fail because it cannot open the shared library
    #export LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64
    ldconfig
    cd ../..
    rm -rf cmocka-1.0.1
    cd "${CUR_PWD}" || exit
}

# Check if /etc/os-release exists and print error message
# For example, NixOS container doesn't have one
if [ ! -f /etc/os-release ]; then
    echo "Unsupported distribution, /etc/os-release does not exist"
    exit 1
fi

# Load OS info
# shellcheck source=/dev/null
. /etc/os-release

if [ "${ID}" = 'debian' ] || [ "${ID_LIKE}" = 'debian' ]; then
    [ "${ID_LIKE}" = 'debian' ] && echo "[*] Detected debian-based distro: ${ID} (${VERSION_ID})"
    [ "${ID}" = 'debian' ] && echo "[*] Detected debian (${VERSION_CODENAME}/${VERSION_ID})"
    if [ "${STEP}" = 'builder' ]; then
        LIBTINFO=$(dpkg -l libtinfo5 > /dev/null 2>&1 && echo libtinfo5)
        [ -z "${LIBTINFO}" ] && LIBTINFO=$(dpkg -l libtinfo6 > /dev/null 2>&1 && echo libtinfo6)

        LIBSSL_PKG=$(dpkg -l libssl3 > /dev/null 2>&1 && echo libssl3)
        [ -z "${LIBSSL_PKG}" ] && LIBSSL_PKG=$(dpkg -l libssl1.1 > /dev/null 2>&1 && echo libssl1.1)

        LIBPCRE_PKG=$(apt search libpcre2-posix 2>/dev/null | grep 'libpcre2-posix' | awk -F/ '{print $1}')

        apt-get update \
        && export DEBIAN_FRONTEND=noninteractive \
        && apt-get -y install --no-install-recommends \
            build-essential autoconf automake libtool pkg-config libnl-3-dev libnl-genl-3-dev libssl-dev \
            ethtool shtool rfkill zlib1g-dev libpcap-dev libsqlite3-dev libpcre2-dev libhwloc-dev \
            libcmocka-dev hostapd wpasupplicant tcpdump screen iw usbutils expect gawk bear \
            "${LIBTINFO}" git python3-setuptools && \
                rm -rf /var/lib/apt/lists/*
    elif [ "${STEP}" = 'stage2' ]; then
        apt-get update && \
        apt-get -y install --no-install-recommends \
            libsqlite3-0 "${LIBSSL_PKG}" hwloc "${LIBPCRE_PKG}" libnl-3-200 libnl-genl-3-200 iw usbutils pciutils \
            iproute2 ethtool kmod wget ieee-data python3 python3-graphviz rfkill && \
        rm -rf /var/lib/apt/lists/*
    fi
elif [ "${ID}" = 'arch' ] || [ "${ID_LIKE}" = 'arch' ]; then
    [ "${ID}" = 'arch' ] && echo "[*] Detected Arch Linux"
    [ "${ID_LIKE}" = 'arch' ] && echo "[*] Detected Arch-based Linux: ${NAME} (${ID})"
    if [ "${STEP}" = 'builder' ]; then
	    pacman -Sy --noconfirm libgpg-error gnupg gpgme glibc
        pacman -Sy --noconfirm base-devel libnl openssl ethtool util-linux zlib libpcap sqlite pcre2 hwloc \
                                cmocka hostapd wpa_supplicant tcpdump screen iw usbutils pciutils expect git \
                                python python-setuptools expat
    elif [ "${STEP}" = 'stage2' ]; then
        pacman -Sy --noconfirm libgpg-error gnupg gpgme glibc
        pacman -Sy --noconfirm libnl openssl ethtool util-linux zlib libpcap sqlite pcre2 hwloc iw usbutils \
                                pciutils python-graphviz python
    fi
elif [ "${ID}" = 'alpine' ]; then
    echo "[*] Detected alpine (${VERSION_ID})"
    if [ "${STEP}" = 'builder' ]; then
        apk add --no-cache \
            gcc g++ make autoconf automake libtool libnl3-dev openssl-dev ethtool libpcap-dev cmocka-dev \
            hostapd wpa_supplicant tcpdump screen iw pkgconf util-linux sqlite-dev pcre2-dev linux-headers \
            zlib-dev pciutils usbutils expect hwloc-dev git python3 gawk bear py3-pip
    elif [ "${STEP}" = 'stage2' ]; then
        apk add --no-cache \
            libnl3 openssl ethtool libpcap util-linux sqlite-dev pcre2 zlib pciutils usbutils hwloc wget \
            iproute2 kmod python3 py3-graphviz urfkill iw
    fi
elif [ "${ID}" = 'fedora' ] || [ "${ID}" = 'almalinux' ] || [ "${ID}" = 'rocky' ] || [ "${ID}" = 'ol' ]; then
    echo "[*] Distribution: ${NAME} (${VERSION_ID})"
    LIBPCAP=libpcap-devel
    CMOCKA=libcmocka-devel
    DNF_BIN=dnf
    type dnf5 >/dev/null 2>&1
    # shellcheck disable=SC2181
    [ $? -eq 0 ] && DNF_BIN=dnf5
    echo "DNF: ${DNF_BIN}"
    ${DNF_BIN} distro-sync -y --refresh
    if [ "${STEP}" = 'builder' ]; then
        if [ "${ID}" = 'almalinux' ] || [ "${ID}" = 'rocky' ]; then
            echo "[*] Install EPEL and enabling CRB"
            ${DNF_BIN} install epel-release dnf-plugins-core -y
            ${DNF_BIN} config-manager --set-enabled crb
            ${DNF_BIN} distro-sync -y --refresh
        elif [ "${ID}" = 'ol' ]; then
            echo "[*] Install EPEL"
            ${DNF_BIN} install epel-release dnf-plugins-core -y
            ${DNF_BIN} install xz cmake gcc wget -y
            LIBPCAP=libpcap
            # We're installing cmocka manually, not present in repos
            CMOCKA=""
            ${DNF_BIN} distro-sync -y --refresh

            export LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64
            install_cmocka
            cd / || exit
        fi

        ${DNF_BIN} install -y libtool pkgconfig sqlite-devel autoconf automake openssl-devel ${LIBPCAP} \
                              pcre2-devel rfkill libnl3-devel gcc gcc-c++ ethtool hwloc-devel ${CMOCKA} \
                              make file expect hostapd wpa_supplicant iw usbutils tcpdump screen zlib-devel \
                              expect python3-pip python3-setuptools git
    elif [ "${STEP}" = 'stage2' ]; then
        GRAPHVIZ=python3-graphviz
        [ "${ID}" != 'fedora' ] && GRAPHVIZ=graphviz-python3
        ${DNF_BIN} install -y libnl3 openssl-libs zlib libpcap sqlite-libs pcre2 hwloc iw ethtool pciutils \
                              usbutils expect python3 ${GRAPHVIZ} iw util-linux ethtool kmod
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
elif [ "${ID}" = 'gentoo' ]; then
    echo "[*] Detected Gentoo"
    export EMERGE_DEFAULT_OPTS="--binpkg-respect-use=y --getbinpkg=y"
    cat <<EOF >/etc/portage/binrepos.conf/osuosl.conf
[binhost]
priority = 9999
sync-uri = https://gentoo.osuosl.org/experimental/amd64/binpkg/default/linux/17.1/x86-64/
EOF
    # shellcheck disable=SC2016
    echo 'FEATURES="${FEATURES} -ipc-sandbox -network-sandbox -pid-sandbox"' >> /etc/portage/make.conf
    if [ ! -d "/etc/portage/gnupg" ]; then
        getuto
    fi
    emerge-webrsync

    if [ "${STEP}" = 'builder' ]; then
        emerge app-portage/elt-patches dev-db/sqlite dev-lang/python dev-libs/libbsd dev-libs/libnl dev-libs/libpcre2 \
                dev-libs/openssl dev-vcs/git net-libs/libpcap net-wireless/iw net-wireless/lorcon sys-apps/hwloc \
                net-wireless/wireless-tools sys-apps/ethtool sys-apps/hwdata sys-apps/pciutils sys-apps/usbutils \
                sys-devel/autoconf sys-devel/automake sys-devel/gnuconfig sys-devel/libtool sys-libs/zlib \
                --jobs="$(nproc)" --quiet
    elif [ "${STEP}" = 'stage2' ]; then
        emerge dev-db/sqlite dev-lang/python dev-libs/libbsd dev-libs/libnl dev-libs/libpcre2 dev-libs/openssl \
                net-libs/libpcap net-wireless/iw net-wireless/lorcon net-wireless/wireless-tools sys-apps/ethtool \
                sys-apps/hwdata sys-apps/hwloc sys-apps/pciutils sys-apps/usbutils sys-libs/zlib app-portage/gentoolkit \
                --jobs="$(nproc)"
        eclean --deep distfiles && eclean --deep packages
        emerge --depclean app-portage/gentoolkit
        rm -fr /var/db/repos/gentoo /etc/portage/binrepos.conf/osuosl.conf
    fi
elif [ "${ID}" = 'clear-linux-os' ]; then
    echo "[*] Detected Clear Linux (${VERSION_ID})"
    if [ "${STEP}" = 'builder' ]; then
        # Break swupd in multiple steps to avoid 'bundle too large by xxxM'
        # Build hostapd
        swupd bundle-add --skip-diskspace-check wget
        swupd bundle-add --skip-diskspace-check c-basic
        swupd bundle-add --skip-diskspace-check devpkg-openssl
        swupd bundle-add --skip-diskspace-check devpkg-libnl
        install_hostapd

        # Install the rest of the packages
        swupd bundle-add --skip-diskspace-check devpkg-libgcrypt
        swupd bundle-add --skip-diskspace-check devpkg-hwloc
        swupd bundle-add --skip-diskspace-check devpkg-libpcap
        swupd bundle-add --skip-diskspace-check devpkg-pcre2
        swupd bundle-add --skip-diskspace-check devpkg-sqlite-autoconf
        swupd bundle-add --skip-diskspace-check git
        swupd bundle-add --skip-diskspace-check ethtool
        swupd bundle-add --skip-diskspace-check network-basic
        swupd bundle-add --skip-diskspace-check software-testing
        swupd bundle-add --skip-diskspace-check sysadmin-basic
        swupd bundle-add --skip-diskspace-check wpa_supplicant
        swupd bundle-add --skip-diskspace-check os-testsuite
                         
    elif [ "${STEP}" = 'stage2' ]; then
        # Break it in multiple steps to avoid 'bundle too large by xxxM'
        swupd bundle-add --skip-diskspace-check libnl
        swupd bundle-add --skip-diskspace-check openssl
        swupd bundle-add --skip-diskspace-check devpkg-zlib
        swupd bundle-add --skip-diskspace-check devpkg-libpcap
        swupd bundle-add --skip-diskspace-check sqlite
        swupd bundle-add --skip-diskspace-check devpkg-pcre2
        swupd bundle-add --skip-diskspace-check hwloc
        swupd bundle-add --skip-diskspace-check ethtool
        swupd bundle-add --skip-diskspace-check network-basic
        swupd bundle-add --skip-diskspace-check sysadmin-basic
        swupd bundle-add --skip-diskspace-check python-extras
    fi
elif [ "${ID}" = 'slackware' ]; then
    echo "[*] Detected Slackware Linux (${VERSION_ID})"
    slackpkg update
    if [ "${STEP}" = 'builder' ]; then
        slackpkg install ca-certificates perl dcron gcc g++ make guile gc wget openssl libnl3 \
                         binutils glibc flex kernel-headers pkg-config cmake libarchive lz4 libxml2
        update-ca-certificates -f
        # Otherwise tests will fail because it cannot open the shared library
        export LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64
        install_hostapd
        install_cmocka
        install_hwloc

        slackpkg install autoconf automake libtool ethtool libmnl libpcap tcpdump libcap-ng dbus pciutils usbutils expect tcl \
            screen util-linux sqlite icu4c libedit pcre2 zlib git python3 gawk python-pip wpa_supplicant expat m4
        pip install setuptools
    elif [ "${STEP}" = 'stage2' ]; then
        slackpkg install ca-certificates perl dcron
        slackpkg install util-linux pciutils usbutils wget iproute2 kmod python3 util-linux python-pip expat ethtool \
                         libmnl glibc libnl3 sqlite icu4c
        slackpkg install make guile gc gcc wget kernel-headers pkg-config  glibc binutils
        update-ca-certificates -f
        pip install graphviz
        install_iw
        slackpkg remove perl dcron make guile gc gcc gcc-brig gcc-g++ gcc-gdc gcc-gfortran gcc-gnat gcc-go gcc-objc \
                        kernel-headers pkg-config binutils
        rm -f /var/lib/slackpkg/*
    fi
else
    echo "[!] Unsupported distro: ${ID} - PR welcome"
    exit 1
fi

# shellcheck disable=SC2181
if [ $? -ne 0 ]; then
    echo '[!] ERROR, aborting'
    exit 1
fi

exit 0
