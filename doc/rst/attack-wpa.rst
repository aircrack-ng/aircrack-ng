WPA attacks
-----------

Standard attack
==========================

Here airoscript will send a deauth attack, so we can get the handshake, and launch airodump-ng to listen for it.

::
    airodump-ng -w DUMP_PATH/HOST_MAC --bssid HOST_MAC --channel CHANNEL -a WIFI_INTERFACE

It will ask you for the kind of deauth attack you want to use (have a look at Authentication) TODO: ADD LINK

You can read more about it on: http://www.aircrack-ng.org/doku.php?id=cracking_wpa&s[]=wpa

WMM Attack
==========
Have in account that this attacks will most probably not work, it an advanced attack not meant for novice users that might need fine-tuning inside airoscript itself.

Got from the aircrack-ng wiki:

::

    Tkiptun-ng is the proof-of-concept implementation the WPA/TKIP attack.
    This attack is described in the paper, Practical attacks against WEP and
    WPA written by Martin Beck and Erik Tews. The paper describes advanced
    attacks on WEP and the first practical attack on WPA. An additional excellent
    references explaining how tkiptun-ng does its magic is this ars technica 
    article Battered, but not broken: understanding the WPA crack by Glenn Fleishman.

    Basically tkiptun-ng starts by obtaining the plaintext of a small packet and 
    the MIC (Message Integrity Check). This is done via chopchop-type method.
    Once this is done, the MICHAEL algorithm is reversed the MIC key used to
    protect packets being sent from the AP to the client can be calculated.

    At this point, tkiptun-ng has recovered the MIC key and knows a keystram
    for access point to client communication. Subsequently, using the XOR file,
    you can create new packets and inject them. The creation and injection are
    done using the other aircrack-ng suite tools. 

You can read more here: http://www.aircrack-ng.org/doku.php?id=tkiptun-ng
