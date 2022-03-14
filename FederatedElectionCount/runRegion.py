#!/usr/bin/env python3
import argparse
import sys
from scapy.all import sendp, send, srp1, sniff, sendp, hexdump, sr, get_if_list, get_if_hwaddr,get_if_addr, bind_layers
import random
import threading
from scapy.all import Packet, hexdump
from scapy.all import Ether, IP, UDP, StrFixedLenField, XByteField, IntField, ByteField
from scapy.all import bind_layers
from time import sleep
from FEC_header import FEC
received = list(range(50))
state_map = ['AL', 'AK', 'AZ', 'AR', 'CA', 'CO', 'CT', 'DE', 'FL', 'GA', 'HI',
       'ID', 'IL', 'IN', 'IA', 'KS', 'KY', 'LA', 'ME', 'MD', 'MA', 'MI',
       'MN', 'MS', 'MO', 'MT', 'NE', 'NV', 'NH', 'NJ', 'NM', 'NY', 'NC',
       'ND', 'OH', 'OK', 'OR', 'PA', 'RI', 'SC', 'SD', 'TN', 'TX', 'UT',
       'VT', 'VA', 'WA', 'WV', 'WI', 'WY']

results = []
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
#
#bind_layers(IP,FEC,proto=FEC_PROTOCOL)
#bind_layers(Ether,IP,type=ETHERTYPE_IPV4)
name2host = {
            "South": "h1", 
            "West": "h2", 
            "PacificNorthWest": "h3", 
            "MidWest": "h4", 
            "NewEngland": "h5", 
            "Citizen": "c1",
            "Legislature1":"m1",
            "Legislature2":"m2",
            "Legislature3":"m3"
    }

port_map = {"h1-eth1":1235, 
        "h2-eth1":1236, 
        "h3-eth1":1237, 
        "h4-eth1":1238, 
        "h5-eth1":1239,
        "b1-eth1":1234,
        "c1-eth1":1240, 
        "m1-eth1":1241, 
        "m2-eth1":1242, 
        "m3-eth1":1243
        }
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


counter = 0
votes = [FEC() for i in range(50)]

def betterSendp(pkt, iface):
    sleep(1)
    sendp(pkt, iface=iface, verbose=False)

def handle_pktm(oldpkt,iface):
    global counter
    global received
    global results
    counter += 1
    if(FEC in oldpkt):
        record = oldpkt.getlayer(FEC)
        state = getattr(record,"state")
        vote_count = getattr(record,"votes")
        counted = getattr(record,"counted")
        phase = getattr(record,"phase")
        candidate = getattr(record,"candidate")
        pkt =  Ether(src=get_if_hwaddr(iface), dst='02:00:00:47:b8:66')/IP(dst="192.0.0.10")/UDP(dport=port_map[iface]+100, sport=port_map[iface])/FEC(state=state,votes=vote_count,counted=counted,phase=3,candidate=candidate)
        record = pkt.getlayer(FEC) 
        if(state in received):
            person = "N"
            if(candidate == 1):
                person = "B"
            vote_count = getattr(record,"votes")
            print(state_map[state]+","+str(vote_count)+","+person+","+str(state))
            received.remove(state)
            
            t = threading.Thread(target = betterSendp, args = (pkt, iface,))
            t.start()
        #if(len(received) == 0):
        #    print("check corresponding csv")
        #    exit(0)
   
        #print("replied: " + str(getattr(record,"state"))+","+str(getattr(record, "votes"))+",candidate:"+str(getattr(record, "candidate")))

    else:
        print("Error invalid packet")
        oldpkt.show2()


def handle_pkt(pkt,iface,resultPath):
    global counter
    global received
    global results
    counter += 1
    if(FEC in pkt):

        record = pkt.getlayer(FEC)
        state = getattr(record,"state") 
        candidate = getattr(record,"candidate")
        person = "N"
        if(candidate == 1):
            person = "B"
        vote_count = getattr(record,"votes")
        votes[state] = record

        if(state in received):
            received.remove(state)
            item = state_map[state]+","+str(vote_count)+","+person+","+str(state)
            print(item)
            results.append(item+"\n")
        if(len(results) == 50):

            print("Finished check corresponding csv")
            with open(resultPath,"w") as f:
                f.writelines(results)
            #exit(-1)
        else:
            print(str(len(results))+" so far")
        #print("counter: " + str(counter) + " received: " + str(getattr(record,"state"))+","+str(getattr(record, "votes"))+",candidate:"+str(getattr(record, "candidate")))
        #pkt.show2()
        #if(counter == 50):
        #    print("finished")
        #    exit(0)
    else:
        print("Error invalid packet")
        pkt.show2()

def send_helper(iface, regionalVotes):
    print("sleeping for 10 seconds for other hosts to prepare")
    sleep(10)
    print("woke up. launching send thread")
    broadcast_addr = "192.0.0.10"
    global received
    global results
    for item in regionalVotes:
        pkt =  Ether(src=get_if_hwaddr(iface),dst='02:00:00:47:b8:66') / IP(dst=broadcast_addr) / UDP(dport=port_map[iface]+100,sport=port_map[iface])
        candidate = 0
        if(item[2] == "B"):
            candidate = 1

        pkt = pkt / FEC(state = int(item[3]),votes = int(item[1]), counted = 0, phase = 0, candidate = candidate)       
        if(int(item[3]) in received):
            received.remove(int(item[3]))
        #pkt.show2()
        sleep(1)
        sendp(pkt, iface = iface,verbose=False)
        record = pkt.getlayer(FEC)
        state = getattr(record,"state") 
        candidate = getattr(record,"candidate")
        person = "N"
        if(candidate == 1):
            person = "B"
        vote_count = getattr(record,"votes")
        item = state_map[state]+","+str(vote_count)+","+person+","+str(state)
        results.append(item+"\n")
        print(item)
        print(str(len(results)) + "so far")
        #print("sent: " + str(getattr(record,"state"))+","+str(getattr(record, "votes"))+",candidate:"+str(getattr(record, "candidate")))
        sleep(1)
    #print("finished sending")
# START THEM ALL, AND HAVE THEM SNIFF FOR A BEGIN PACKET FROM BROADCASTER.  AFTER BROADCASTER RECEIVES ACK, BROADCASTER SENDS ACK BACK, AND BEGIN IN HANDLE

def main():
    global port_map
    if len(sys.argv) != 2:
        print('pass one of the following as argument "South", "West", "PacificNorthWest", "MidWest", "NewEngland", "Citizen", "Legislature1", "Legislature2, "Legislature3""')
        exit(1)

    region = sys.argv[1]
    
    print(get_if_list())
    iface = get_if("eth")
    print(iface)
    bind_layers(UDP,FEC,sport=port_map[iface])
   
    resultPath="regionalCSVs/"  + region + "/" + region + "results.csv"
    #fork thread, have it send, sniff on main and reaccumulate and print result
    if(name2host[region] not in ["c1","m1","m2","m3"]):
        # do first handler that does this handshake scheme
        regionalVotes = []
        with open("regionalCSVs/"  + region + "/" + region + ".csv","r") as f:
            regionalVotes = [item[:-1].split(",") for item in f.readlines()[1:]]
            #print(regionalVotes)
        t = threading.Thread(target = send_helper, args = (iface,regionalVotes,))
        t.start()
    
    print("sniffing on " + iface)
    if(name2host[region] not in ["m1", "m2", "m3"]):
        sniff(iface = iface,
            prn = lambda x: handle_pkt(x,iface, resultPath))

    else:
        sniff(iface = iface,
            prn = lambda x: handle_pktm(x,iface))

if __name__ == '__main__':
    main()

