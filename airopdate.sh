#! /bin/bash

# Program:	Airopdate                                                          
# Authors:	Base Code by Daouid
# Date:	        15.05.2007

#The path where the data is stored (FOLDER MUST EXIST !)
DUMP_PATH="/wifi"

# leave this alone (if you edit this, it will screw up the menu)
CHOICES="1 2 3 4 5"


function chooseversion {
while true; do
  clear
  echo "#######################################"
  echo "###   Select aircrack-ng version    ###"
  echo "###                                 ###"
  echo "###   1) Latest 0.9 branch          ###"
  echo "###   2) Latest 1.0-dev             ###"
  echo "###   3) Specific revision          ###"
  echo "###   4) Latest Stable              ###"
  echo "###                                 ###"
  echo "#######################################"
  read yn
  case $yn in
    1 ) latest09 ; break ;;
    2 ) latest10 ; break ;;
    3 ) svnrev ; break ;;
    4 ) stable ; break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
function latest09 {
svn co http://trac.aircrack-ng.org/svn/trunk/ aircrack-ng-svn
cd aircrack-ng-svn
make clean
make uninstall
make
make install
cd ..
}
function latest10 {
svn co http://trac.aircrack-ng.org/svn/branch/1.0-dev aircrack-ng-dev
cd aircrack-ng-dev
make clean
make uninstall
make
make install
cd ..
}
function svnrev {
  echo "#######################################"
  echo "###     Input revision number       ###"
  echo "#######################################"
read rev
echo You typed: $rev
set -- ${rev}

svn co -r $rev http://trac.aircrack-ng.org/svn/trunk/ aircrack-ng-r"$rev"
cd aircrack-ng-rev
make clean
make uninstall
make
make install
cd ..
}

function stable {
svn co http://trac.aircrack-ng.org/svn/tags/0.9 aircrack-ng-stable
cd aircrack-ng-stable
make clean
make uninstall
make
make install
cd ..
}

function airoscript {
svn co http://trac.aircrack-ng.org/svn/branch/airoscript/ airoscript
cd airoscript
chmod +x airoscript.sh
cd ..
}

function choosedriver {
while true; do
  clear
  echo "#######################################"
  echo "###  Select driver/chipset version  ###"
  echo "###                                 ###"
  echo "###   1) ASPj's rt2570 drivers      ###"
  echo "###   2) rt2500 drivers             ###"
  echo "###                                 ###"
  echo "#######################################"
  read yn
  case $yn in
    1 ) rt2570 ; break ;;
    2 ) rt2500 ; break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}

function rt2570 {
ifconfig rausb0 down
rmmod rt2570
wget http://homepages.tu-darmstadt.de/~p_larbig/wlan/rt2570-k2wrlz-1.6.0.tar.bz2
tar -xvjf rt2570-k2wrlz-1.6.0.tar.bz2
cd rt2570-k2wrlz-1.6.0/Module
make && make install
modprobe rt2570
cd ..
}

function rt2500 {
ifconfig ra0 down
rmmod rt2500
wget http://rt2x00.serialmonkey.com/rt2500-cvs-daily.tar.gz
tar -xvzf rt2500-cvs-daily.tar.gz
cd rt2500-cvs-**********/Module
make && make install
modprobe rt2500
cd $DUMP_PATH
}

function menufonction {
xterm $HOLD $TOPRIGHT -title "Fake function to jump to menu" -e echo "Aircrack-ng is a great tool, Mister_X ASPj HIRTE are GODS"
}
# menu listing command	
function menu {
  echo "###########################################"
  echo "### What do you want to do?             ###"
  echo "### 1) Aircrack-ng - Get aircrack-ng    ###"
  echo "### 2) Drivers     - Get drivers        ###"
  echo "### 3) Airoscript  - Get airoscript     ###"
  echo "### 4) Quit        - Exit this script   ###"		
}
#######################################################################
# script start
	
	mkdir $DUMP_PATH
	cd $DUMP_PATH
	menu	
select choix in $CHOICES; do					
	if [ "$choix" = "1" ]; then
	chooseversion
	menu			
	elif [ "$choix" = "2" ]; then
	choosedriver
	menu					
	elif [ "$choix" = "3" ]; then
	airoscript
	menu	
	elif [ "$choix" = "4" ]; then
	echo Script terminated
exit			
	else
	clear
	menu
        echo "#######################################"
        echo "###      Wrong number entered       ###"
	fi
done
#END

