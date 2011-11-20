Crack
------


This section defines cracking menu.

Note: If "pipe" variable is set, it will be executed and piped into aircrack-ng (that's the way the john the ripper plugin works, actually)

Note: If writekey variable contains a set of commands to write the key to a file (wich is default on auto)

WPA Crack
==========

It will execute attacks against a wordlist.

WEP Crack
=========

Default
++++++++

Executes aircrack-ng with the following options

::                  

    "$pipe $AIRCRACK -0 -a 1 -b $Host_MAC -f $FUDGEFACTOR -l $DUMP_PATH/$Host_MAC.key -0 -s $DUMP_PATH/$Host_MAC-01.cap $crack_extra_opts $writekey"; $clear; break ;;


Korek
++++++

Executes aircrack-ng with the following options

AIRCRACK -0 -a 1 -b $Host_MAC -f $FUDGEFACTOR -l $DUMP_PATH/$Host_MAC.key -0 -s $DUMP_PATH/$Host_MAC-01.cap -K $crack_extra_opts $writekey

Interactive
+++++++++++

Same as default, except that it allows you to enter personalized fudge_factor and enc_size.

Executes aircrack-ng with the following options:

::
   AIRCRACK -0 -a 1 -b $Host_MAC -f $FUDGEFACTOR -l $DUMP_PATH/$Host_MAC.key -0 -s $DUMP_PATH/$Host_MAC-01.cap -K $crack_extra_opts $writekey 
