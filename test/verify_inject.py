#!/usr/bin/env python2
# Usage: https://github.com/aircrack-ng/aircrack-ng/pull/21

from scapy.all import *
conf.verbf = 1

interface = "at0"

rpkt = Ether( dst = "[AP mac]", src = "[STA mac]" )/\
       IP( dst = "[AP ip]", src = "[STA ip]" )/\
       UDP( )/\
       DNS(rd=1,qd=DNSQR(qname="www.aircrack-ng.org"))
sendp( rpkt, iface = interface )
