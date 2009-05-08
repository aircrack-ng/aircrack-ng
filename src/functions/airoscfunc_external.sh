#!/bin/bash
# Unstable functions file for airoscript.
# Requires: wlandecrypter 

# Copyright (C) 2009 David Francos Cuartero
#        This program is free software; you can redistribute it and/or
#        modify it under the terms of the GNU General Public License
#        as published by the Free Software Foundation; either version 2
#        of the License, or (at your option) any later version.

#        This program is distributed in the hope that it will be useful,
#        but WITHOUT ANY WARRANTY; without even the implied warranty of
#        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#        GNU General Public License for more details.

#        You should have received a copy of the GNU General Public License
#        along with this program; if not, write to the Free Software
#        Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

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
