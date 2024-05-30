# Docker container to test WPE patch against a specific version of freeradius, then create an updated patch if successful.
# Build args:
# - OLD_VERSION: old hostapd version
# - NEW_VERSION: new hostapd version

# hadolint ignore=DL3006
FROM kalilinux/kali-rolling

ARG OLD_VERSION
ARG NEW_VERSION

RUN if [ -z "${OLD_VERSION}" ]; then \
  >&2 printf  "\nOLD_VERSION build argument not set\n"; \
  exit 1; \
  fi

RUN if [ -z "${NEW_VERSION}" ]; then \
  >&2 printf  "\nNEW_VERSION build argument not set\n"; \
  exit 1; \
  fi

RUN if [ "${NEW_VERSION}" = "${OLD_VERSION}" ]; then \
  >&2 print  "\nNew version and old version cannot be identical!\n"; \
  exit 1; \
  fi


# hadolint ignore=DL3005,DL3015,DL3008
RUN apt-get update && apt-get dist-upgrade -y && \
	apt-get install -y wget patch make gcc \
		libssl-dev build-essential libtalloc-dev libpcre2-dev libsqlite3-dev \
		libhiredis-dev libykclient-dev libyubikey-dev default-libmysqlclient-dev \
		libcurl4-openssl-dev libperl-dev libpam0g-dev libcap-dev libmemcached-dev \
		libgdbm-dev unixodbc-dev libpq-dev libwbclient-dev libkrb5-dev libjson-c-dev \
		freetds-dev samba-dev libcollectdclient-dev libldap-dev && \
	apt-get autoclean && \
	rm -rf /var/lib/apt/lists/*

# Download and unpack
WORKDIR /tmp
# hadolint ignore=DL4006,SC2046
RUN wget -nv https://github.com/FreeRADIUS/freeradius-server/releases/download/release_$(echo ${NEW_VERSION} | tr '.' '_')/freeradius-server-${NEW_VERSION}.tar.bz2
RUN tar -xjf freeradius-server-${NEW_VERSION}.tar.bz2
# hadolint ignore=DL3059
RUN cp -R freeradius-server-${NEW_VERSION} freeradius-server-${NEW_VERSION}-wpe

# Download and apply patch
# hadolint ignore=DL3059
RUN wget -nv https://raw.githubusercontent.com/aircrack-ng/aircrack-ng/master/patches/wpe/freeradius-wpe/freeradius-server-${OLD_VERSION}-wpe.diff
WORKDIR /tmp/freeradius-server-${NEW_VERSION}-wpe
RUN patch --no-backup-if-mismatch -Np1 -i ../freeradius-server-${OLD_VERSION}-wpe.diff


# Create updated patch
WORKDIR /tmp/
# hadolint ignore=SC2046
RUN if [ $(diff -rupN freeradius-server-${NEW_VERSION} freeradius-server-${NEW_VERSION}-wpe > freeradius-server-${NEW_VERSION}-wpe.diff) -eq 2 ]; then \
		echo "diff failed"; \
		ext 1; \
	fi

# Ensure it compiles
WORKDIR /tmp/freeradius-server-${NEW_VERSION}-wpe
RUN ./configure
# hadolint ignore=DL3059,SC2046
RUN make -j $(nproc)

# Then copy patch to /output
WORKDIR /tmp
RUN mkdir /output && mv  freeradius-server-${NEW_VERSION}-wpe.diff /output
WORKDIR /output