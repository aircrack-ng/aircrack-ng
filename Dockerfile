# hadolint ignore=DL3007
FROM kalilinux/kali-rolling:latest AS builder

# Install dependencies for building
# hadolint ignore=DL3008
RUN apt-get update \
 && export DEBIAN_FRONTEND=noninteractive \
 && apt-get -y install --no-install-recommends \
      build-essential autoconf automake libtool pkg-config libnl-3-dev libnl-genl-3-dev libssl-dev \
	  ethtool shtool rfkill zlib1g-dev libpcap-dev libsqlite3-dev libpcre3-dev libhwloc-dev \
	  libcmocka-dev hostapd wpasupplicant tcpdump screen iw usbutils expect gawk bear \
	  libtinfo5 python3-pip git && \
	  	rm -rf /var/lib/apt/lists/*

# Build Aircrack-ng
RUN mkdir -p /aircrack-ng /output
COPY . /aircrack-ng
WORKDIR /aircrack-ng
# hadolint ignore=SC2006
RUN set -x \
	&& make distclean || : && \
		autoreconf -vif && \
		set -e; \
			./configure --with-experimental --with-ext-scripts --enable-maintainer-mode --without-opt --prefix=/usr && \
			make -j3 && \
		set +e && \
			if ! make check -j3; then \
				echo "Processor: $(uname -m)"; \
				for file in `grep -l "(exit status: [1-9]" test/*.log`; do \
					echo "[*] Test ${file}:"; \
					cat "${file}"; \
				done; \
				exit 1; \
			fi && \
		set -e && \
			make install DESTDIR=/output

# Stage 2
# hadolint ignore=DL3007
FROM kalilinux/kali-rolling:latest

COPY --from=builder /output/usr /usr

# Install dependencies
# hadolint ignore=DL3008
RUN set -x \
 && apt-get update && \
	apt-get -y install --no-install-recommends \
		libsqlite3-0 libssl3 hwloc libpcre3 libnl-3-200 libnl-genl-3-200 iw usbutils pciutils \
		iproute2 ethtool kmod wget ieee-data python3 python3-graphviz rfkill && \
	rm -rf /var/lib/apt/lists/* && \
	aircrack-ng -u
