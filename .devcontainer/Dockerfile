# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.154.2/containers/cpp/.devcontainer/base.Dockerfile

# [Choice] Debian / Ubuntu version: debian-10, debian-9, ubuntu-20.04, ubuntu-18.04
ARG VARIANT="buster"
FROM mcr.microsoft.com/vscode/devcontainers/cpp:0-${VARIANT}

ARG CLANGURL="https://releases.llvm.org/3.8.1/"
ARG CLANGFILE="clang+llvm-3.8.1-x86_64-linux-gnu-ubuntu-16.04.tar.xz"

RUN apt-get update \
 && export DEBIAN_FRONTEND=noninteractive \
 && apt-get -y install --no-install-recommends \
      build-essential autoconf automake libtool pkg-config libnl-3-dev libnl-genl-3-dev libssl-dev \
	  ethtool shtool rfkill zlib1g-dev libpcap-dev libsqlite3-dev libpcre3-dev libhwloc-dev \
	  libcmocka-dev hostapd wpasupplicant tcpdump screen iw usbutils expect gawk bear \
	  libtinfo5 \
	  clangd-10 \
	  clang-format-10 \
	  python3-pip \
 && rm -rf /var/lib/apt/lists/* \
 && /usr/bin/pip3 install pre-commit \
 && cd /tmp \
 && wget "${CLANGURL}/${CLANGFILE}" \
 && tar -x --strip-components=1 -C /usr/local -J -f ${CLANGFILE} \
 && rm -f ${CLANGFILE}
