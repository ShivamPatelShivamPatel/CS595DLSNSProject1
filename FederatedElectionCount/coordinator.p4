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
    /*register< bit<1> >(300) has; 
    register< int<32>>(6) host_index
    action has_qm(int<32> host_index, bit<1> op_flag) {
    	bit<32> index = (bit<32>)hdr.fec.state + 50 * (bit<32>)host_index; //2d array trick
	if(op_flag == 0){
	    has.write(index, 1); 
	}
	else{
	    bit<1> has_seen;
	    has.read(has_seen,index);
	    if(has_seen == 1){
	        drop();
	    }
	    else{
		has.write(index, 1); 
            }
	}
    }

    table ip_has {
    	key = {
	    hdr.ipv4.src : exact;
	    hdr.ipv4.dst : exact;
        }
	actions = { has_qm; NoAction; }
	default_action = NoAction;
	const entries = {
	    (0xC0000005,0xC000000A) : has_qm(0,0);//,hdr.fec.state); //192.0.0.5
	    (0xC0000006,0xC000000A) : has_qm(1,0);//,hdr.fec.state); //192.0.0.6
	    (0xC0000007,0xC000000A) : has_qm(2,0);//,hdr.fec.state); //192.0.0.7
	    (0xC0000008,0xC000000A) : has_qm(3,0);//,hdr.fec.state); //192.0.0.8
	    (0xC0000009,0xC000000A) : has_qm(4,0);//,hdr.fec.state); //192.0.0.9
	    (0xC000000B,0xC000000A) : has_qm(5,0);//,hdr.fec.state); //192.0.0.11
	    (0xC000000A,0xC0000005) : has_qm(0,1);//,hdr.fec.state); //192.0.0.5
	    (0xC000000A,0xC0000006) : has_qm(1,1);//,hdr.fec.state); //192.0.0.6
	    (0xC000000A,0xC0000007) : has_qm(2,1);//,hdr.fec.state); //192.0.0.7
	    (0xC000000A,0xC0000008) : has_qm(3,1);//,hdr.fec.state); //192.0.0.8
	    (0xC000000A,0xC0000009) : has_qm(4,1);//,hdr.fec.state); //192.0.0.9
	    (0xC000000A,0xC000000B) : has_qm(5,1);//,hdr.fec.state); //192.0.0.11
	}
    }*/

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
	    if(hdr.fec.phase == 0 || hdr.fec.phase == 1){
	    	hdr.fec.phase = hdr.fec.phase + 1;
		/*if(hdr.fec.phase == 0){
		    ip_has.apply();
		}*/
	    }
	    else if(hdr.fec.phase == 3){
	        int<32> count;
		records.read(count, (bit<32>)hdr.fec.state);
		if(count < 2){
		    count = count + 1;
		    records.write((bit<32>)hdr.fec.state, count);
		    if(count == 2){
		        hdr.fec.phase = 4;
		    }
		    else{ // we havent seen 2 votes yet so drop it
			drop();
		    }
		}
		else{ // we have seen 2 votes so drop it
		    drop();
		}
            }
	    /*
	    else{ // phase is 4 if dst has seen or had, it drops, else it marks it for that host as has seen
		//ip_has.apply();
	    }*/
	}
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
