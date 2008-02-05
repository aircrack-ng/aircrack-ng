The AirCrack suite provided has been modified to work in conjunction with the AirPcap adapters and the drivers included in the AirPcap CD.

aireplay-ng requires an AirPcap Tx adapter to be able to function while all the other tools can use either adapter.


Binary Locations
----------------

	The aircrack-ng binaries are located in the "bin" folder and they are fully AirPcap capable.

	
Usage Instructions
------------------

	The adapter name you need to use is \\.\airpcapXX, where XX is the number of the AirPcap device.
	For example:

	airodump-ng.exe \\.\airpcap00 airpcap 0 trace
	or
	aireplay-ng --fakeauth 0 -e "MYSSID" -a 11:22:33:44:55:66 -h 66:55:44:33:22:11 \\.\airpcap00


More Information
----------------

	Official website: 		www.aircrack-ng.org
	Aircrack-ng introduction: 	www.aircrackng.org/doku.php?id=newbie_guide
	WEP attack guide: 		www.aircrackng.org/doku.php?id=simple_wep_crack
	Getting started guide:          www.aircrack-ng.org/doku.php?id=getting_started
	Official AirPcap Website:	www.cacetech.com

How to build the sources Instructions
-------------------------------------

1. Install cygwin from http://www.cygwin.com/
2. Download the AirPcap Develper's pack from http://www.cacetech.com/support/downloads.htm
3. Unpack the AirPcap Develper's pack inside the main aircrack folder, and rename the new directory to "AirPcap_Devpack"
4. Open a bash shell
5. run "make -f Makefile.airpcap"