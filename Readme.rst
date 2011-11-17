===============
 Airoscript-ng
===============

---------------------------------------------
User interface to aircrack-ng
---------------------------------------------

:Author: This manual page was written by David Francos <me@davidfrancos.net>
:Date:   2011-11-17
:Copyright: David Francos Cuartero
:Version: 1.1
:Manual section: 1
:Manual group: net

SYNOPSIS
========

airoscript-ng [-h] [-t TERMINAL] [-v] [-w WIRELESS_CARD] [-b] [-m fakemac|realmac] [-a] [-n FILTER] [-x] [-z] [-p PLUGIN_FILE]

DESCRIPTION
===========

Airoscript is a complete user interface for aircrack-ng.

It gives you almost all functionality that aircrack-ng has, allowing you to
save some time from writting commands. Writing commands may be good to learn
how does it work, but repeatedly doing so can damage your mind and your body.

Airoscript also provides a comprehensive way to generate CEO-readable network
security reports, writable (by wkhtml2pdf plugin) as pdf.

OPTIONS
=======


-h                    Show this message
-t terminal           Specify terminal (xterm or screen)
-v                    Verbose & debug mode
-w wireless_card      Specify wifi card
-b                    Writes a csv file with network data.
-m mac_mode           Change mac to fakemac before everything else. (mac mode can be fakemac or realmac)
-a                    Automatic mode
-n regex              Filter SSID by regex
-x                    Autoconfigure network after automatic crack (requires -a)
-z                    Don't scan automatically at start
           

Examples
========

Crack the first of all my test networks using my own mac

    ::

        airoscript-ng -w wlan0 -m realmac -n "XayOnTest_(.*)" 
        
Try to crack any network with faked mac. Warning, this may
conduct you to commit a crime

    ::

        airoscript-ng -w wlan0 -m fakemac -a 

.. The following one is a little bigger
    - It loads digenpy plugin (wich means that if a network can be cracked with a dictionary provided by digenpy, it will wait for only FOUR packages, then crack it with dict)
    - It forces to use xterm interface (wich, by the way, is the default stuff)
    - Uses wlan1 as interface
    - Writes a csv file with the network data for posterior analysis
    - Uses your real mac
    - Starts debugging mode (it just prints out more information than usual (ugly as hell, meant for dev))
    - Autoconfigures network after cracking. This SHOULD NOT DO ANYTHING IN THIS EXAMPLE (auto mode), as at the end of automatic mode, it already asks you to configure it. 
    
    airoscript-ng -t xterm -v -w wlan1 -b -m realmac -a -n "XayOn_" -x -pdigenpy

Developers
==========

| Help and feedback is greatly appreciated. 
| Please feel free to mail XayOn at xayon@xayon.net 

Compliance
==========

In the wrong hands, airoscript and aircrack-ng could easily violate the 
government certification of your radio. 
A simple example of this is running injection on frequencies your
radio isn't certified for in your geographic region.

You and only you are responsible for making sure that your tools *including*
*airoscript* are compliant with the regulations in your country and region.

Bugs and feature requests
=========================

Please submit bugs in aircrack-ng trac or aircrack-ng oficial forum "airoscript
support" subforum.

Menu usage
==========

Airoscript-ng menu is quite intuitive, and it's documented in the html docs.
Since version 1.1 is able to queue commands, that is, you can tell it
to do 1 then 2 in a menu just by entering "1 2" (without the quotes).

Configuration
=============

There are 2 configuration files, airoscript-ng.conf and
airoscript-ng_advanced.conf that are well explained within them.

.. this is for the manpage, sorry for the inconvenience

.. include:: doc/install
 
Plugin support
==============

Airoscript supports plugins, shell scripts listed in enabled_plugins on 
airoscript configuration (use the full path there).

Since svn revision 1969 airoscript-ng has a plugin menu, wich will make you
able to enable any plugin after airoscript has been started just by
selecting it.

Currently (at 1991) the plugin list that comes out with airoscript is:

   - arpspoof --> Enables arp spoof menu
   - digenpy --> Enables digenpy dictionary generator for cracking
   - dsniff --> launches dsniff (better use it with arpspoof and sslstrip)
   - hydra --> Configures network, then launches hydra to get router password
   - iptables --> Configures iptables to redirect trough it (needed for arpspoof sslstrip)
   - johntheripper --> Enables john the ripper to generate password lists for cracking WPA
   - mdk3 --> Enables mdk3 menu
   - sslstrip --> Enables sslstrip menu 
   - tcpdstat --> When making a report, includes tcpdstat's protocol statistics
   - wkhtmltopdf --> Converts reports to pdf 
   - zenity --> Enables a zenity-based graphical interface for airoscript-ng (needs also libnotify-bin)
   - pyrit --> a raw interface for pyrit, requires pyrit knowledge

Creating a plugin 
=================

For a plugin to add a menu entry, you'll have to set
$plugins_menu["Title of the menu you want to use"] to an array of
the entries you want to add.

Have a look at http://xayon.net/adding-nessus-support-to-airoscript/ for
a more complete tutorial.

SEE ALSO
========

.. _airoscript-ng homepage: http://airoscript.aircrack-ng.org/
.. _airoscript-ng google code: http://code.google.com/p/airoscript
.. _XayOns blog: http://www.xayon.net

| airoscript.conf(1)
| airdecap-ng(1)
| airdriver-ng(1)
| aireplay-ng(1)
| airmon-ng(1)
| airodump-ng(1)
| airolib-ng(1)
| airsev-ng(1)
| airtun-ng(1)
| buddy-ng(1)
| easside-ng(1)
| ivstools(1)
| kstats(1)
| makeivs-ng(1)
| packetforge-ng(1)
| wesside-ng(1)
| aircrack-ng(1)

