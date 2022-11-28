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
RUN mkdir /aircrack-ng && \
	mkdir /output
COPY . /aircrack-ng
RUN cd /aircrack-ng && \
	autoreconf -i && \
	./configure --with-experimental --with-ext-scripts --prefix=/output && \
	make && \
	make check && \
	make install

# Stage 2
FROM kalilinux/kali-rolling
COPY . /usr/src/aircrack-ng

# XXX: Copying /output to / does not work, bash fails to start
COPY --from=builder /output/share /share
COPY --from=builder /output/sbin /sbin
COPY --from=builder /output/lib /lib
COPY --from=builder /output/include /include
COPY --from=builder /output/bin /bin

# Install dependencies
RUN apt update && \
	apt -y install --no-install-recommends \
		libsqlite3-0 libssl3 hwloc libpcre3 libnl-3-200 libnl-genl-3-200 iw usbutils pciutils \
		iproute2 ethtool kmod wget ieee-data python3 python3-graphviz rfkill && \
	rm -rf /var/lib/apt/lists/*
