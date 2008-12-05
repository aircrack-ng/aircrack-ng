#! /bin/bash
export TEXTDOMAINDIR=/usr/share/locale
export TEXTDOMAIN=airoscript
# Program:	Airoscript                                                          
# Authors:	Base Code by Daouid; Mods & Tweaks by CurioCT and others; Continued by XayOn.
# Credits:      Hirte, Befa, Stouf, Mister_X, ASPj , Andrea, Pilotsnipes, darkAudax, Atheros support thx to green-freq
# Date of this version:	        27.11.2008
# Version of aircrack-ng required:  AIRCRACK-NG 1.0.2
# Dependencies: aircrack-ng, xterm|urxvt|gnome-terminal|... , grep, awk, macchanger, drivers capable of injection (for injection =) ), mdk3 (optional), wlandecrypter (optional)

function confwarn {
echo -n -e "`gettext 'Youre going to use a config file on your home or current dir. 
This may be harmfull, for example, if your user have been 
compromised, and youre getting rights trought sudo, someone
can modify your config file to do something malicious as 
root. Be sure to check your home config file before using it. 
Defaults on /etc/airoscript.conf should be ok so you can 
safely remove your ~/.airoscript.conf\n\n
Do you really want to do it (yes/No): '`"
}

# Get config.
if [ -e ~/.airoscript.conf ];
	then 	
		if [ $HOME != "/root" ]
		then
			confwarn
			read response
			if [ "$response" = "yes" ]
				then
					. ~/.airoscript.conf
				else
					echo `gettext "Ok, please remove/rename your $HOME/.airoscript.conf"`
					exit
			fi
		else
			. ~/.airoscript.conf
		fi
	else
		if [ -e /etc/airoscript.conf ]; then
			. /etc/airoscript.conf
		else
			if [ -e airoscript.conf ]; then
				confwarn
				read response
				if [ "$response" = "yes" ]
				then
					. airoscript.conf
				else
					echo -e `gettext "Ok, please remove/rename your $HOME/.airoscript.conf"`
					exit
				fi
			else
				echo -e `gettext "Error, no config file found, quitting"`
				exit
			fi
		fi
fi

# include functions, functions value is on config file.
if [ -e $FUNCTIONS ]; then
	. $FUNCTIONS
else
	echo -e "[ERROR] : Functions file does not exists, quitting\n"
	exit
fi

# get theme, theme value is on config file
if [ -e $THEMEDIR/$THEME.theme ]; then
	. $THEMEDIR/$THEME.theme 
else
	echo -e "[WARN] : theme file does not exists, using defaults...\n" 
	DUMPING_COLOR="#FFFFFF"
	INJECTION_COLOR="#1DFF00"
	ASSOCIATION_COLOR="#FF0009"
	DEAUTH_COLOR="#99CCFF"
	BACKGROUND_COLOR="#000000"
fi

#runs debug routine to set $HOLD value
debug

#checks if output dir exists, if not, it creates it.
checkdir

#Ask for screen size
reso

#checks if interface is set, if not it ask you
setinterface

#displays main menu
menu

# Sets ps3, wich will be shown after input in the select	
PS3=`gettext 'Input number: '`
select choix in $CHOICES; do					
	if [ "$choix" = "1" ]; then
		choosetype
		clear
		menu			

	elif [ "$choix" = "2" ]; then
		if [ -e $DUMP_PATH/dump-01.txt ]	
		then
			Parseforap
			clear
			if [ "$Host_SSID" = $'\r' ]
	 			then blankssid;
			elif [ "$Host_SSID" = "No SSID has been detected" ]
				then blankssid;
			fi
			target
			choosetarget
			clear
			menu
		else
			clear
			echo "ERROR: You have to scan for targets first"
			menu
		fi

	elif [ "$choix" = "3" ]; then
		witchattack	
		menu

	elif [ "$choix" = "4" ]; then
		witchcrack
		menu	

	elif [ "$choix" = "5" ]; then
		echo launching fake auth commands
		choosefake && menu	

	elif [ "$choix" = "6" ]; then	
		choosedeauth
		menu

	elif [ "$choix" = "7" ]; then
		optionmenu
		menu

	elif [ "$choix" = "8" ]; then
		injectmenu
		menu
	elif [ "$choix" = "9" ]; then
		doauto
		menu

	elif [ "$choix" = "10" ]; then
		echo -n `gettext "	Do you want me to stop monitor mode on $WIFI? (y/N) "`
		read dis
		if [ "$dis" = "y" ]
		then
			echo -n `gettext 'Deconfiguring interface...'`
			airmon-ng stop $WIFI
		fi
		echo -n `gettext 'Do you want me to delete temporary data dir? (y/N) '`
		read del

		if [ "$del" = "y" ]
		then
			echo -n `gettext 'Deleting'` " $DUMP_PATH ..."
			rm -r $DUMP_PATH
			rm *.cap
			echo `gettext 'done'`
		fi

		exit
	else
		clear
		menu
        echo "`gettext \"#######################################\"`"
        echo "`gettext \"###      Wrong number entered       ###\"`"
	fi
done
