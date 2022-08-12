# Docker container to test WPE patch against a specific version of hostapd, then create an updated patch if successful.
# Build args:
# - OLD_VERSION: old hostapd version
# - NEW_VERSION: new hostapd version

FROM kalilinux/kali-rolling

ARG OLD_VERSION
ARG NEW_VERSION

RUN if [ -z "${OLD_VERSION}" ]; then \
  >&2 echo  "\nOLD_VERSION build argument not set\n"; \
  exit 1; \
  fi

RUN if [ -z "${NEW_VERSION}" ]; then \
  >&2 echo  "\nNEW_VERSION build argument not set\n"; \
  exit 1; \
  fi

RUN if [ "${NEW_VERSION}" = "${OLD_VERSION}" ]; then \
  >&2 echo  "\nNew version and old version cannot be identical!\n"; \
  exit 1; \
  fi

# Download required packages  
RUN ln -f -s /usr/share/zoneinfo/UTC /etc/localtime
RUN apt update && apt dist-upgrade -y && \
	apt install wget patch make gcc libssl-dev libnl-genl-3-dev \
		libnl-3-dev pkg-config libsqlite3-dev -y && \
	apt autoclean && \
	rm -rf /var/lib/apt/lists/*

# Download and unpack
WORKDIR /tmp
RUN wget https://w1.fi/releases/hostapd-${NEW_VERSION}.tar.gz
RUN tar -zxf hostapd-${NEW_VERSION}.tar.gz
RUN cp -R hostapd-${NEW_VERSION} hostapd-${NEW_VERSION}-wpe

# Download and apply patch
RUN wget https://github.com/aircrack-ng/aircrack-ng/raw/master/patches/wpe/hostapd-wpe/hostapd-${OLD_VERSION}-wpe.patch
WORKDIR /tmp/hostapd-${NEW_VERSION}-wpe
RUN patch  --no-backup-if-mismatch -p1 < ../hostapd-${OLD_VERSION}-wpe.patch

# Create updated patch
WORKDIR /tmp/
RUN if [ $(diff -rupN hostapd-${NEW_VERSION} hostapd-${NEW_VERSION}-wpe/ > hostapd-${NEW_VERSION}-wpe.patch) -eq 2 ]; then \
		echo "diff failed"; \
		ext 1; \
	fi

# Ensure it compiles
WORKDIR /tmp/hostapd-${NEW_VERSION}-wpe/hostapd
RUN cd hostapd-${NEW_VERSION}/hostapd && make

# Then copy patch to /output
RUN mkdir /output && mv hostapd-${NEW_VERSION}-wpe.patch /output/hostapd-${NEW_VERSION}-wpe.patch
