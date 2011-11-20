Advanced tools
================

Advanced aircrack-ng tools (not frequently used), aircrack-ng tools that are available in a less-customizable manner in other menus, and diagnostics tools are presented here.

Injection
+++++++++

Chop chop and fragmentation attacks. 
Those are only usable when you already have xor files.

About chopchop attack (got from aircrack-ng wiki):

:: 

    This attack, when successful, can decrypt a WEP data packet without knowing the key. It can even work against dynamic WEP. This attack does not recover the WEP key itself, but merely reveals the plaintext. However, some access points are not vulnerable to this attack. Some may seem vulnerable at first but actually drop data packets shorter that 60 bytes. If the access point drops packets shorter than 42 bytes, aireplay tries to guess the rest of the missing data, as far as the headers are predictable. If an IP packet is captured, it additionally checks if the checksum of the header is correct after guessing the missing parts of it. This attack requires at least one WEP data packet.

.. _ChopChop on aircrack-ng wiki: http://www.aircrack-ng.org/doku.php?id=korek_chopchop

About frag attack (got from aircrack-ng wiki):

::
    This attack, when successful, can obtain 1500 bytes of PRGA (pseudo random generation algorithm). This attack does not recover the WEP key itself, but merely obtains the PRGA. The PRGA can then be used to generate packets with packetforge-ng which are in turn used for various injection attacks. It requires at least one data packet to be received from the access point in order to initiate the attack.

.. _Fragmentation attack on aircrack-ng wiki: http://www.aircrack-ng.org/doku.php?id=fragmentation


Autentication
++++++++++++++

This will provide Fake auth and Deauth attacks.

Fake auth attack, from aircrack-ng wiki:

::

   The fake authentication attack allows you to perform the two types of WEP authentication (Open System and Shared Key) plus associate with the access point (AP). This is only useful when you need an associated MAC address in various aireplay-ng attacks and there is currently no associated client. It should be noted that the fake authentication attack does NOT generate any ARP packets. Fake authentication cannot be used to authenticate/associate with WPA/WPA2 Access Points.

.. _Fake auth attack on aircrack-ng wiki: http://www.aircrack-ng.org/doku.php?id=fake_authentication

Deauth attack, from aircrack-ng wiki:

:: 

    This attack sends disassocate packets to one or more clients which are currently associated with a particular access point. Disassociating clients can be done for a number of reasons:
    - Recovering a hidden ESSID. This is an ESSID which is not being broadcast. Another term for this is “cloaked”.
    - Capturing WPA/WPA2 handshakes by forcing clients to reauthenticate
    - Generate ARP requests (Windows clients sometimes flush their ARP cache when disconnected)
    - Of course, this attack is totally useless if there are no associated wireless client or on fake authentications.

.. _Deauth attack on aircrack-ng wiki: http://www.aircrack-ng.org/doku.php?id=deauthentication


Operations with ivstools
++++++++++++++++++++++++

Makes it possible to merge ivs (with ivstools) from either one airoscript session or all the previous saved ones.

Decloak packages
+++++++++++++++++

Launches a nice selection menu about airdecloack-ng options.

.. _Airdecloack-ng on aircrack-ng wiki: http://www.aircrack-ng.org/doku.php?id=airdecloak-ng

:: 
    Airdecloak-ng is a tool that removes wep cloaking from a pcap file. Some WIPS (actually one) actively “prevent” cracking a WEP key by inserting chaff (fake wep frames) in the air to fool aircrack-ng. In some rare cases, cloaking fails and the key can be recovered without removing this chaff. In the cases where the key cannot be recovered, use this tool to filter out chaff.

Create virtual interface with airtun-ng
++++++++++++++++++++++++++++++++++++++++

Creates a virtual interface with the cracked wep key using airtun-ng.

Diagnostics and reports
++++++++++++++++++++++++

This menu makes airgraph-ng reports.

Auto crack wep with wesside-ng 
+++++++++++++++++++++++++++++++

Launches wesside-ng to try to auto-crack the network.

::
    
    Wesside-ng is an auto-magic tool which incorporates a number of techniques to seamlessly obtain a WEP key in minutes. It first identifies a network, then proceeds to associate with it, obtain PRGA (pseudo random generation algorithm) xor data, determine the network IP scheme, reinject ARP requests and finally determine the WEP key. All this is done without your intervention.

.. _Wesside-ng at aircrack-ng wiki: http://www.aircrack-ng.org/doku.php?id=wesside-ng

Easside-ng
+++++++++++

An auto-magic tool which allows you to communicate via an WEP-encrypted AP without knowing the key
.. _easside-ng at aircrack-ng wiki: http://www.aircrack-ng.org/doku.php?id=easside-ng
