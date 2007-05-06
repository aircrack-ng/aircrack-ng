#! /bin/bash

echo "Welcome to aircrack-ng auto SVN updater"
echo "This script will checkout latest revisions of aircrack-ng and airoscript"
echo "After the checkout it will clean, uninstall, compile and reinstall aircrack-ng"
echo "It will also chmod airoscript for you"
echo "two folders will be created: aircrack-ng and airoscript"
cd ..
svn co http://trac.aircrack-ng.org/svn/trunk/ aircrack-ng
cd aircrack-ng
make clean
make uninstall
make
make install
cd ..
svn co http://trac.aircrack-ng.org/svn/branch/airoscript/ airoscript
cd airoscript
chmod +x airoscript.sh
