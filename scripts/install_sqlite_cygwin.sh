# This script automatically install and patch SQLite
# in a cygwin environment.
#

# Requirements: All requirements from Aircrack-ng 
#               INSTALL file must be installed.
#
# Author: Thomas d'Otreppe de Bouvette (Aircrack-ng)


#!/bin/sh

SQLITE_VERSION="3.6.11"
SQLITE_PATCH=sqlite-3.6.11-lib_cygwin.diff
CURR_PWD="`pwd`"
OSNAME="`uname -s | sed -e 's/.*CYGWIN.*/cygwin/g'`"

if [ "$OSNAME" != "cygwin" ]; then
	echo "This is not cygwin, aborting."
	echo "Patching is only required in a cygwin environment."
	exit
fi

cd /tmp
rm -rf sqlite-${SQLITE_VERSION}*
wget http://www.sqlite.org/sqlite-${SQLITE_VERSION}.tar.gz
tar -zxf sqlite-${SQLITE_VERSION}.tar.gz
cd sqlite-${SQLITE_VERSION}
./configure --disable-tcl
wget http://patches.aircrack-ng.org/${SQLITE_PATCH}
patch -i $SQLITE_PATCH
make
sleep 1s
make install
cd ..
cd $CURR_PWD
echo INSTALLATION COMPLETE