from scapy.all import *
import sys, os

FEC_PROTOCOL = 0x91
UDP_PROTOCOL = 0x11
ETHERTYPE_IPV4 = 0x0800
DPORT = 0x4d2
class FEC(Packet):
    name = "FEC"
    fields_desc = [ IntField("state",0),
                    IntField("votes",0),
                    IntField("counted",0),
                    IntField("phase",0),
                    IntField("candidate",0)
            ]

bind_layers(UDP, FEC)#, dport = DPORT)
bind_layers(IP, UDP, proto=UDP_PROTOCOL)
bind_layers(Ether,IP,type=ETHERTYPE_IPV4)

