#include "Parsing.p4"
#include "EmptyBMDefinitions.p4"

#define WIDTH_PORT_NUMBER 9

parser CompleteParser(packet_in pkt, out headers_t hdr, inout booster_metadata_t m, inout metadata_t meta) {
    state start {
        ALVParser.apply(pkt, hdr);
        transition accept;
    }
}

control Process(inout headers_t hdr, inout booster_metadata_t m, inout metadata_t meta) {
    register< int<32> >(50) records;

    action mac_forward_set_egress(bit<WIDTH_PORT_NUMBER> port) {
        meta.egress_spec = port;
    }

    table mac_forwarding {
        key = {
            hdr.eth.dst : exact;
        }
        actions = {
            mac_forward_set_egress;
            NoAction;
        }
    }

    bit<32> dst_gateway_ipv4 = 0;

    action ipv4_forward(bit<32> next_hop, bit<WIDTH_PORT_NUMBER> port) {
        meta.egress_spec = port;
        dst_gateway_ipv4 = next_hop;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_forwarding {
        key = {
            hdr.ipv4.dst : ternary;
        }
        actions = {
            ipv4_forward;
            NoAction;
        }
    }

    action arp_lookup_set_addresses(bit<48> mac_address) {
        hdr.eth.src = hdr.eth.dst;
        hdr.eth.dst = mac_address;
    }

    table next_hop_arp_lookup {
        key = {
            dst_gateway_ipv4 : exact;
        }
        actions = {
            arp_lookup_set_addresses;
            NoAction;
        }
    }


    apply {
	if (hdr.fec.isValid()){
	    if(hdr.fec.phase == 2){
	      int<32> seen;
	      records.read(seen, (bit<32>)hdr.fec.state);
		if(seen == 0){
		    seen = 1;
		    records.write((bit<32>)hdr.fec.state, seen);
		}
		else{
	    	  drop();
	        }
	    }
	    if(hdr.fec.phase == 1){
	    	drop();
            }
	}
	// if made it to this point, then we just saw it, fliped packet src and dst and sending back for s1 to count that 2/3 of fed gov verified
        if (hdr.eth.isValid()) {
            if (mac_forwarding.apply().hit) return;
            if (hdr.ipv4.isValid() &&
                  hdr.ipv4.ttl > 1 &&
                  ipv4_forwarding.apply().hit) {
                if (next_hop_arp_lookup.apply().hit) {
                    return;
                }
            }
        }
        drop();
    }
}

V1Switch(CompleteParser(), NoVerify(), Process(), NoEgress(), ComputeCheck(), ALVDeparser()) main;
