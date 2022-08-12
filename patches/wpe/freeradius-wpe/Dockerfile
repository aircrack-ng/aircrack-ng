# Docker container to test WPE patch against a specific version of freeradius, then create an updated patch if successful.
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



RUN apt update && apt dist-upgrade -y && \
	apt install -y wget patch make gcc \
		libssl-dev build-essential libtalloc-dev libpcre3-dev libsqlite3-dev \
		libhiredis-dev libykclient-dev libyubikey-dev default-libmysqlclient-dev \
		libcurl4-openssl-dev libperl-dev libpam0g-dev libcap-dev libmemcached-dev \
		libgdbm-dev unixodbc-dev libpq-dev libwbclient-dev libkrb5-dev libjson-c-dev \
		freetds-dev samba-dev libcollectdclient-dev libldap-dev && \
	apt autoclean && \
	rm -rf /var/lib/apt/lists/*

# Download and unpack
WORKDIR /tmp
RUN wget https://github.com/FreeRADIUS/freeradius-server/releases/download/release_$(echo ${NEW_VERSION} | tr '.' '_')/freeradius-server-${NEW_VERSION}.tar.bz2
RUN tar -xjf freeradius-server-${NEW_VERSION}.tar.bz2
RUN cp -R freeradius-server-${NEW_VERSION} freeradius-server-${NEW_VERSION}-wpe

# Download and apply patch
RUN wget https://raw.githubusercontent.com/aircrack-ng/aircrack-ng/master/patches/wpe/freeradius-wpe/freeradius-server-${OLD_VERSION}-wpe.diff
WORKDIR /tmp/freeradius-server-${NEW_VERSION}-wpe
RUN patch --no-backup-if-mismatch -Np1 -i ../freeradius-server-${OLD_VERSION}-wpe.diff


# Create updated patch
WORKDIR /tmp/
RUN if [ $(diff -rupN freeradius-server-${NEW_VERSION} freeradius-server-${NEW_VERSION}-wpe > freeradius-server-${NEW_VERSION}-wpe.diff) -eq 2 ]; then \
		echo "diff failed"; \
		ext 1; \
	fi

# Ensure it compiles
WORKDIR /tmp/freeradius-server-${NEW_VERSION}-wpe
RUN ./configure
RUN make

# Then copy patch to /output
WORKDIR /tmp
RUN mkdir /output && mv  freeradius-server-${NEW_VERSION}-wpe.diff /output
