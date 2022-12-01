FROM kalilinux/kali-rolling AS builder

# Install dependencies for building
RUN apt-get update \
 && export DEBIAN_FRONTEND=noninteractive \
 && apt-get -y install --no-install-recommends \
      build-essential autoconf automake libtool pkg-config libnl-3-dev libnl-genl-3-dev libssl-dev \
	  ethtool shtool rfkill zlib1g-dev libpcap-dev libsqlite3-dev libpcre3-dev libhwloc-dev \
	  libcmocka-dev hostapd wpasupplicant tcpdump screen iw usbutils expect gawk bear \
	  libtinfo5 python3-pip git

# Build Aircrack-ng
RUN mkdir -p /aircrack-ng /output
COPY . /aircrack-ng
RUN set -x \
 && cd /aircrack-ng && \
	make distclean || : && \
	autoreconf -vif && \
	set -e; \
		./configure --with-experimental --with-ext-scripts --enable-maintainer-mode --without-opt --prefix=/usr && \
		make -j3 && \
		make check -j3 && \
		make install DESTDIR=/output

# Stage 2
FROM kalilinux/kali-rolling

COPY --from=builder /output/usr /usr

# Install dependencies
RUN set -x \
 && apt update && \
	apt -y install --no-install-recommends \
		libsqlite3-0 libssl3 hwloc libpcre3 libnl-3-200 libnl-genl-3-200 iw usbutils pciutils \
		iproute2 ethtool kmod wget ieee-data python3 python3-graphviz rfkill && \
	rm -rf /var/lib/apt/lists/* && \
	aircrack-ng -u
