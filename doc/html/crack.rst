Crack
------

.. image:: images/crack.png

This section defines cracking menu.
Note: If "pipe" variable is set, it will be executed and piped into aircrack-ng (that's the way the john the ripper plugin works, actually)

WPA Crack
==========

.. image:: images/wpa_crack.png

WEP Crack
=========

.. image:: images/wep_crack.png

Default
++++++++

Default option passes

Executes
::                  

    "$pipe $AIRCRACK -0 -a 1 -b $Host_MAC -f $FUDGEFACTOR -l $DUMP_PATH/$Host_MAC.key -0 -s $DUMP_PATH/$Host_MAC-01.cap $crack_extra_opts $writekey"; $clear; break ;;


Korek
++++++

Interactive
+++++++++++
