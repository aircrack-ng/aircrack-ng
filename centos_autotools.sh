#!/bin/sh

AUTO_INSTALL=0

is_installed() {
	yum list installed $1 >/dev/null 2>/dev/null
	if [ $? -eq 1 ]; then
		if [ ${AUTO_INSTALL} -eq 1 ]; then
			yum install $1
			if [ $? -ne 0 ]; then
				echo "Failed installing $1, aborting"
				exit 1
			fi
		else
			echo "$1 is missing"
			exit 1
		fi
	fi
}

is_installed epel-release
is_installed tar
is_installed wget
is_installed glib2-devel
is_installed gcc
is_installed g++
is_installed make

autoconf_version=2.69
automake_version=1.16.1
libtool_version=2.4.6
pkgconf_version=0.29

echo "Installing autoconf ${autoconf_version}"
wget http://ftp.gnu.org/gnu/autoconf/autoconf-${autoconf_version}.tar.xz \
 && tar xJf autoconf-${autoconf_version}.tar.xz \
 && cd autoconf-${autoconf_version} \
 && ./configure --prefix=/usr/local \
 && make \
 && make install \
 && cd ..


echo "Installing automake ${automake_version}"
wget http://ftp.gnu.org/gnu/automake/automake-${automake_version}.tar.xz \
 && tar xJf automake-${automake_version}.tar.xz \
 && cd automake-${automake_version} \
 && ./configure --prefix=/usr/local \
 && make \
 && make install \
 && cd ..

echo "Installing libtool ${libtool_version}"
wget http://ftp.gnu.org/gnu/libtool/libtool-${libtool_version}.tar.xz \
 && tar xJf libtool-${libtool_version}.tar.xz \
 && cd libtool-${libtool_version} \
 && ./configure --prefix=/usr/local \
 && make \
 && make install \
 && cd ..

echo "Installing pkg-config ${pkgconf_version}"
wget https://pkg-config.freedesktop.org/releases/pkg-config-${pkgconf_version}.tar.gz \
 && tar xzf pkg-config-${pkgconf_version}.tar.gz \
 && cd pkg-config-${pkgconf_version} \
 && ./configure --prefix=/usr/local --libdir=/usr/lib64 \
 && make \
 && make install \
 && cd ..

echo 'Done'
