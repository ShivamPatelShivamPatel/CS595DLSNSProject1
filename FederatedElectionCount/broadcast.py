#!/usr/bin/env python3
import argparse
import sys
import struct
import os
import random
from scapy.all import sniff, sendp, hexdump, sr, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField, ByteField
from scapy.all import Ether, IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR
import threading
from FEC_header import FEC
from time import sleep

legislativeSwitches = ["192.0.0.2","192.0.0.3","192.0.0.4"]
legislativeHosts = ["192.0.0.12","192.0.0.13","192.0.0.14"]
regionalHosts = ["192.0.0.5","192.0.0.6","192.0.0.7","192.0.0.8","192.0.0.9"]
citizenHosts = ["192.0.0.11"]
centralSwitches = ["192.0.0.1"]

port_map = {"192.0.0.5":1235, "192.0.0.6":1236, "192.0.0.7":1237, "192.0.0.8":1238, "192.0.0.9":1239, "192.0.0.11":1240, "192.0.0.12":1241, "192.0.0.13":1242, "192.0.0.14":1243}




has_map = {ip:[False for i in range(50)] for ip in legislativeSwitches + legislativeHosts + regionalHosts + citizenHosts + centralSwitches}
#FEC_PROTOCOL = 0x91
#ETHERTYPE_IPV4 = 0x0800

#class FEC(Packet):
#    name = "FEC"
#    fields_desc = [ IntField("state",0),
#                    IntField("votes",0),
#                    IntField("counted",0),
#                    IntField("phase",0),
#                    IntField("isBoris",0),
#                    IntField("isNik",0)
#            ]

#bind_layers(IP,FEC,proto=FEC_PROTOCOL)
#bind_layers(Ether,IP,type=ETHERTYPE_IPV4)

def broadcast(oldpkt,iface,l):
    sleep(1)
    for addr in l:
        print(("sending on interface {} to IP addr {}".format(iface, str(addr))))
        record = oldpkt.getlayer(FEC)
        #if(has_map[addr][int(getattr(record,"state"))] and addr in l):
        #    print("ip: " + addr + " " + "already has state: " + str(getattr(record,"state")))
        #    continue
        #else:
        #    has_map[addr][int(getattr(record,"state"))] = True
        state = getattr(record,"state")
        votes = getattr(record,"votes")
        counted = getattr(record,"counted")
        phase = getattr(record,"phase")
        candidate = getattr(record,"candidate")
        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')/IP(dst=addr)/UDP(sport=port_map[addr]+100, dport=port_map[addr])/FEC(state=state,votes=votes,counted=counted,phase=phase,candidate=candidate)
        record = pkt.getlayer(FEC)
        print("sending: " + str(getattr(record,"state"))+","+str(getattr(record, "votes"))+",candidate:"+str(getattr(record, "candidate")))
        sendp(pkt, iface=iface, verbose=False)
    print("done broadcasting")
    return

def get_if(host_iface):
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if host_iface in i:
            iface=i
            break;
    if not iface:
        print("Cannot find " + host_iface + " interface")
        exit(1)
    return iface

def broad_cast_helper(pkt,iface):
#   hexdump(pkt)
#   print "len(pkt) = ", len(pkt)
    if(FEC in pkt):
        record = pkt.getlayer(FEC)
        phase = getattr(record, "phase")
        print("receved: " + str(getattr(record,"state"))+","+str(getattr(record, "votes"))+",candidate:"+str(getattr(record, "candidate")))
        ip = ""
        src = getattr(pkt.getlayer(IP),"src") 
        dst = getattr(pkt.getlayer(IP),"dst")
        if(src == "192.0.0.10"):
            ip = dst
        else:
            ip = src
        print(ip)
        if(phase == 1):
            print("in phase 1")
            for addr in legislativeHosts + [ip]:
                if (has_map[addr][int(getattr(record,"state"))]):
                    print(addr + " has it")
                else:
                    print("addr is")
                    print(addr)
                    has_map[addr][int(getattr(record,"state"))] = True
                    broadcast(pkt, iface, [addr])
        else: 
            tmp = regionalHosts + citizenHosts
            for addr in tmp:
                if (has_map[addr][int(getattr(record,"state"))]):
                    print(addr + " has it")
                else:
                    print("addr is")
                    print(addr)
                    has_map[addr][int(getattr(record,"state"))] = True
                    broadcast(pkt, iface, [addr])
        #broadcast(pkt, iface, tmp)
        #else:
        #    print("not phase 1 and not phase 3. received phase: " + str(phase) + ".  droping...")
        #    pkt.show2()
    else:
        print("Error no layer FEC")
        pkt.show2()
    #if(ip in citizenHosts):
    #    broadcast("yo",iface,citizenHosts)
    #elif (ip in regionalHosts):
    #    broadcast("yo",iface,regionalHosts)
    #elif (ip in legislativeHosts):
    #    broadcast("yo",iface,legislativeHosts)
    #else:
    #    print("dropping...")
    sys.stdout.flush()

def handle_pkt(pkt, iface):
    print("in handle packet received: ")
    if Ether in pkt:
        eth = pkt["Ether"]
        print("src eth: " + getattr(eth, "src"))
        print("dst eth: " + getattr(eth, "dst"))
    if IP in pkt:
        ip = pkt["IP"]
        print("src IP: " + getattr(ip, "src"))
        print("dst IP: " + getattr(ip, "dst"))
    t = threading.Thread(target = broad_cast_helper, args = (pkt,iface,))
    t.start()

def main():
    #parser = argparse.ArgumentParser()
    #parser.add_argument('--host_iface', type=str, default="eth1", help='The host interface use')
    #args = parser.parse_args()
    print(has_map)
    iface = get_if("b1-eth1")
    print(("sniffing on %s" % iface))
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x,iface))

if __name__ == '__main__':
    main()
