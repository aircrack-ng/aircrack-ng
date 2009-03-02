#! /bin/bash
# Program:	Airoscript                                                          
# Authors:	Base Code by Daouid; Mods & Tweaks by CurioCT and others; Continued by XayOn.
# Credits:      Hirte, Befa, Stouf, Mister_X, ASPj , Andrea, Pilotsnipes, darkAudax, Atheros support thx to green-freq
# Date of this version:	        27.11.2008
# Version of aircrack-ng required:  AIRCRACK-NG 1.0.2
# Dependencies: aircrack-ng, xterm|urxvt|gnome-terminal|..., awk, macchanger, drivers capable of injection (for injection =) ), mdk3 (optional), wlandecrypter (optional), jazzteldecrypter (optional), grep (included on almost all systems by default)

# $CLEAR screen first of all
$CLEAR
# Set variables for airoscript's locale
export TEXTDOMAINDIR=/usr/share/locale
export TEXTDOMAIN=airoscript
# Sets ps3, wich will be shown after input in the select	
PS3=`gettext 'Input number: '`

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
if [ -e ~/.airoscript/airoscript.conf ];
	then 	
		if [ $HOME != "/root" ]
		then
			confwarn
			read response
			if [ "$response" = "yes" ]
				then
					. ~/.airoscript/airoscript.conf
				else
					echo `gettext "Ok, please remove/rename your $HOME/.airoscript/airoscript.conf"`
					exit
			fi
		else
			. ~/.airoscript/airoscript.conf
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

cd $DUMP_PATH

# Now, if terminal is provided by $1, replace terminal from config with $1
if [ "$1" != "" ]
then
	export TERMINAL=$1
fi

# include functions, functions value is on config file.
if [ -e $FUNCTIONS ]; then
	. $FUNCTIONS
else
	echo -e "`gettext '[ERROR] : Functions file does not exists, quitting'`\n"
	exit
fi

# get theme, theme value is on config file
if [ -e $THEMEDIR/$THEME.theme ]; then
	. $THEMEDIR/$THEME.theme 
else
	echo -e "`gettext '[WARN] : theme file does not exists, using defaults...'`\n" 
	DUMPING_COLOR="#FFFFFF"
	INJECTION_COLOR="#1DFF00"
	ASSOCIATION_COLOR="#FF0009"
	DEAUTH_COLOR="#99CCFF"
	BACKGROUND_COLOR="#000000"
fi


#checks if output dir exists, if not, it creates it.
checkdir

if [ "$TERMINAL" = "screen" ]
then
	if [ -e ~/.airoscript/screen_has_started ]
	then
		rm ~/.airoscript/screen_has_started
	else
		touch ~/.airoscript/screen_has_started
		screen -S airoscript -c $SCREENRC airoscript screen
		$CLEAR
		echo `gettext 'Airoscript is terminating...'`
		exit
	fi


fi

#Ask for screen size
reso

#runs debug routine to set $HOLD value
debug

#checks if interface is set, if not it ask you
setinterface

# Checks if mac is fakemac
checkforcemac

select choix in $CHOICES; do					
	if [ "$choix" = "1" ]; then
		choosetype
		$CLEAR
		menu			

	elif [ "$choix" = "2" ]; then
		if [ -e $DUMP_PATH/dump-01.csv ]	
		then
			Parseforap
			$CLEAR
			if [ "$Host_SSID" = $'\r' ]
	 			then blankssid;
			elif [ "$Host_SSID" = "No SSID has been detected" ]
				then blankssid;
			fi
			target
			choosetarget
			$CLEAR
			menu
		else
			$CLEAR
			echo "`gettext 'ERROR: You have to scan for targets first'`"
			menu
		fi

	elif [ "$choix" = "3" ]; then
		witchattack	
		menu

	elif [ "$choix" = "4" ]; then
		witchcrack
		menu	

	elif [ "$choix" = "5" ]; then
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
		echo -n " "
		read dis
		if [ "$dis" = "y" ]
		then
			echo -n `gettext 'Deconfiguring interface...'` 
			echo -n " "
			airmon-ng stop $WIFI > /dev/null
			echo "`gettext 'done'`"
		fi
		echo -n `gettext 'Do you want me to delete temporary data dir? (y/N) '`
		echo -n " "
		read del

		if [ "$del" = "y" ]
		then
			echo -n `gettext 'Deleting'` " $DUMP_PATH ... "
			rm -r $DUMP_PATH 2>/dev/null
			rm *.cap 2>/dev/null
			echo `gettext 'done'`
		fi

		exit

	elif [ "$choix"="11" ]; then
		if [ $UNSTABLE = "1" ]; then
			$CLEAR
			unstablemenu
			menu
		else
			$CLEAR
			echo "`gettext 'ERROR: Wrong number entered'`"
			menu
		fi
	else
		$CLEAR
		echo "`gettext 'ERROR: Wrong number entered'`"
		menu
	fi
done
