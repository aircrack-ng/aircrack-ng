#! /bin/bash
# Program:	Airoscript                                                          
# Authors:	Base Code by Daouid; Mods & Tweaks by CurioCT and others; Continued by XayOn.
# Credits:      Hirte, Befa, Stouf, Mister_X, ASPj , Andrea, Pilotsnipes, darkAudax, Atheros support thx to green-freq
# Date of this version:	        15.11.2008
# Version of aircrack-ng required:  AIRCRACK-NG 1.0.2
# Dependencies: aircrack-ng, xterm|urxvt|gnome-terminal|... , grep, awk, macchanger, drivers capable of injection (for injection =) ), mdk3 (optional)

# Get config.
if [ -e ~/.airoscript.conf ];
	then 	
		if [ $HOME != "/root" ] 
		then
			echo -e "\t\tYou're going to use a config file on your home dir. 
		This may be harmfull, for example, if your user have been 
		compromised, and you're getting rights trought sudo, someone
		can modify your config file to do something malicious as 
		root. Be sure to check your home config file before using it. 
		Defaults on /etc/airoscript.conf should be ok so you can 
		safely remove your ~/.airoscript.conf\n\n
		Do you really want to do it (Yes/No) (Case sensitive)"

			read response

			if [ $response = "Yes" ]
				then
					. ~/.airoscript.conf
				else
					echo "Ok, quitting, please remove/rename your $HOME/.airoscript.conf"
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
				. airoscript.conf
			else
				echo -e "Error, no config file found, quitting"
				exit
			fi
		fi
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

# include functions, functions value is on config file.
if [ -e $FUNCTIONS ]; then
	. $FUNCTIONS
	if [ -e $UNSTABLEF ]; then
		. $UNSTABLEF
	fi
else
	echo -e "[ERROR] : Functions file does not exists, quitting\n"
	exit
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

select choix in $CHOICES; do					
	if [ "$choix" = "1" ]; then
		choosetype
		choosescan
		clear
		menu			

	elif [ "$choix" = "2" ]; then
		Parseforap
		clear
		choosetarget
		if [ "$Host_SSID" = $'\r' ]
 			then blankssid;
			target
			menu
		elif [ "$Host_SSID" = "No SSID has been detected!" ]
			then blankssid;
			target
			menu
		else
			target
			echo " "
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
		wld
		menu
	else
		clear
		menu
        echo "#######################################"
        echo "###      Wrong number entered       ###"
	fi
done
