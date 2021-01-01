#!/bin/sh
# Install newer version of autotools, automake, libtool, and pkgconfig on CentOS 7

if [ ! -f /etc/os-release ]; then
	echo 'os-release not present, aborting'
	exit 1
fi

. /etc/os-release

# Untested on Red Hat
if [ "x${ID}" != 'xcentos' ] && [ "x${ID}" != 'xredhat' ]; then
	echo 'OS is not CentOS or Red Hat, aborting'
	exit 1
fi

if [ "x${VERSION_ID}" != 'x7' ]; then
	echo "Invalid CentOS/Red Hat version. Expected 7, got ${VERSION_ID}, aborting"
	exit 1
fi

yum install epel-release

# Install packages if not already present
# Yeah, automake is required to build a newer version of automake
PACKAGES="tar glib2-devel gcc gcc-c++ make m4 perl-Data-Dumper help2man automake"
NB_INSTALLED_PKG=$(yum list install ${PACKAGES} | sed -n '/Installed Packages/,$p' | wc -l)
# Count includes the "Installed Packages" line, so decreasing count by 1
NB_INSTALLED_PKG=$((NB_INSTALLED_PKG-1))
NB_PKG=$(echo ${PACKAGES} | wc -w)
[ ${NB_PKG} -ne ${NB_INSTALLED_PKG} ] && yum install ${PACKAGES}

autoconf_version=2.69
automake_version=1.16.1
libtool_version=2.4.6
pkgconf_version=0.29

TMP_DIR=$(mktemp -d)
cd ${TMP_DIR}

echo "Installing autoconf ${autoconf_version}"
curl -L http://ftp.gnu.org/gnu/autoconf/autoconf-${autoconf_version}.tar.xz > autoconf-${autoconf_version}.tar.xz \
 && tar xJf autoconf-${autoconf_version}.tar.xz \
 && cd autoconf-${autoconf_version} \
 && ./configure --prefix=/usr/local \
 && make \
 && make install \
 && cd ..

# Requires autoconf 2.65+
echo "Installing automake ${automake_version}"
curl -L http://ftp.gnu.org/gnu/automake/automake-${automake_version}.tar.xz > automake-${automake_version}.tar.xz \
 && tar xJf automake-${automake_version}.tar.xz \
 && cd automake-${automake_version} \
 && ./configure --prefix=/usr/local \
 && make \
 && make install \
 && cd ..

echo "Installing libtool ${libtool_version}"
curl -L http://ftp.gnu.org/gnu/libtool/libtool-${libtool_version}.tar.xz > libtool-${libtool_version}.tar.xz \
 && tar xJf libtool-${libtool_version}.tar.xz \
 && cd libtool-${libtool_version} \
 && ./configure --prefix=/usr/local \
 && make \
 && make install \
 && cd ..

echo "Installing pkg-config ${pkgconf_version}"
curl -L https://pkg-config.freedesktop.org/releases/pkg-config-${pkgconf_version}.tar.gz > pkg-config-${pkgconf_version}.tar.gz \
 && tar xzf pkg-config-${pkgconf_version}.tar.gz \
 && cd pkg-config-${pkgconf_version} \
 && ./configure --prefix=/usr/local --libdir=/usr/lib64 \
 && make \
 && make install \
 && cd ..

echo 'Done'
