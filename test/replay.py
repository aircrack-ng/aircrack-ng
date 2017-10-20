#!/usr/bin/env python

import sys
import pcapy
from scapy import *
from impacket.ImpactDecoder import *

try:
    conf.verb=0
except NameError:
    # Scapy v2
    from scapy.all import *
    conf.verb=0

if len(sys.argv) != 2:
    print "Usage: ./replay.py <iface>"
    sys.exit(1)

interface=sys.argv[1]

max_bytes = 2048
promiscuous = False
read_timeout = 100 # in milliseconds
packet_limit = -1 # infinite

pc = pcapy.open_live(interface, max_bytes, promiscuous, read_timeout)

def recv_pkts(hdr, data):
    replay = True

    if data[11] == "\xFF":
        return

    # separate ethernet header and ieee80211 packet
    raw_header = data[:11] + "\xFF" + data[12:14]
    header = Ether(raw_header)

    try:
        # end of separation
        packet = Dot11(data[14:])
    except struct.error:
        # Ignore unpack errors on short packages
        return

    # manipulate/drop/insert dot11 packet
    print packet.summary()
    # end of manipulation

    # construct packet and replay
    if replay == True:
        data = header/packet
        sendp(data, iface=interface)

pc.loop(packet_limit, recv_pkts) # capture packets

