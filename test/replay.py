#!/usr/bin/env python

import sys
from scapy import *
conf.verb=0

if len(sys.argv) != 2:
    print "Usage: ./replay.py <iface>"
    sys.exit(1)

interface=sys.argv[1]

while 1:
    replay = True
    data = sniff(iface=interface,count=1)
    if len(data) == 0:
        sys.exit(0)

    # separate ethernet header and ieee80211 packet
    raw_header = str(data[0])[:14]
    header = Ether(raw_header)

    packet = Dot11(str(data[0])[14:])
    # end of separation

    # manipulate/drop/insert dot11 packet
    # 
    # end of manipulation

    # construct packet and replay
    if replay == True:
        data = header/packet
        sendp(data, iface=interface)
