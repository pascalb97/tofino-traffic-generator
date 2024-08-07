#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "headers.p4"
#include "util.p4"

struct headers {
    pktgen_timer_header_t timer;
    pktgen_port_down_header_t port_down;
    ethernet_h ethernet;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
    pkt_gen_t pkt_gen;
}

struct ingress_metadata_t {
    bit<32> src_mask;
    bit<32> dst_mask;
}
struct egress_metadata_t {}

parser SwitchIngressParser(
    packet_in pkt,
    out headers hdr,
    out ingress_metadata_t meta,
    out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);

        pktgen_port_down_header_t pktgen_pd_hdr = pkt.lookahead<pktgen_port_down_header_t>();
        transition select(pktgen_pd_hdr.app_id) {
            1 : parse_pktgen_timer;
            2 : parse_pktgen_timer;
            3 : parse_pktgen_port_down;
            4 : parse_pktgen_port_down;
            default : reject;
        }
    }

    state parse_pktgen_timer {
        pkt.extract(hdr.timer);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_UDP: parse_udp;
            IP_PROTOCOLS_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract( hdr.udp);
        transition accept;
    }
    


    state parse_pktgen_port_down {
        pkt.extract(hdr.port_down);
        transition accept;
    }
}

control SwitchIngress(
    inout headers hdr,
    inout ingress_metadata_t meta,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    action drop() {
        ig_dprsr_md.drop_ctl = 0x1;
    }

    action match(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    table t {
        key = {
        hdr.timer.pipe_id : exact;
        hdr.timer.app_id : exact;
        hdr.timer.batch_id : exact;
        hdr.timer.packet_id : exact;
        ig_intr_md.ingress_port : exact;
        }
        actions = {
            match;
            @defaultonly drop;
        }
        const default_action = drop();
        size = 1024;
    }

    table p {
        key = {
            hdr.port_down.pipe_id : exact;
            hdr.port_down.app_id : exact;
            hdr.port_down.port_num : exact;
            hdr.port_down.packet_id : exact;
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            match;
            @defaultonly drop;
        }
        const default_action = drop();
        size = 1024;
    }

    apply {
        if (hdr.timer.isValid()) {
            t.apply();
        } else if (hdr.port_down.isValid()) {
            p.apply();
        } else {
            drop();
        }
    }
}

control SwitchIngressDeparser(
    packet_out pkt,
    inout headers hdr,
    in ingress_metadata_t meta,
    in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    apply {
        pkt.emit(hdr);
    }
}

parser SwitchEgressParser(
    packet_in pkt,
    out headers hdr,
    out ingress_metadata_t meta,
    out egress_intrinsic_metadata_t eg_intr_md) {

    TofinoEgressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, eg_intr_md);
        transition parse_ethernet;
    }

    state parse_pkt_gen {
        pkt.extract(hdr.pkt_gen);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_UDP: parse_udp;
            IP_PROTOCOLS_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}


/* Define the random IP address generation */
control SwitchEgress(
    inout headers hdr,
    inout ingress_metadata_t meta,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {

    Random<bit<32>>() src_rand;
    Random<bit<32>>() dst_rand;

    bit<32> src_mask = 0;
    bit<32> dst_mask = 0;

    action replace_ip_address(bit<32> s_mask, bit<32> d_mask) {
            src_mask = s_mask;
            dst_mask = d_mask;
    }

    table egress_table {
        key = {
            eg_intr_md.egress_port: exact;
        }
        actions = {
            replace_ip_address;
        }
        size = 64;
    }

    apply {
        if(egress_table.apply().hit) {
            // get random 32 bit number and make bitwise AND with network mask
            bit<32> s_tmp = src_rand.get() & ~src_mask;
            bit<32> d_tmp = dst_rand.get() & ~dst_mask;

            // apply random sub ip string to ip address
            hdr.ipv4.src_addr = hdr.ipv4.src_addr | s_tmp;
            hdr.ipv4.dst_addr = hdr.ipv4.dst_addr | d_tmp;
        }
    }
}

control SwitchEgressDeparser(
    packet_out pkt,
    inout headers hdr,
    in ingress_metadata_t meta,
    in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {

    Checksum() ipv4_checksum;

    apply {
        hdr.ipv4.hdr_checksum = ipv4_checksum.update(
            {hdr.ipv4.version,
             hdr.ipv4.ihl,
             hdr.ipv4.diffserv,
             hdr.ipv4.total_len,
             hdr.ipv4.identification,
             hdr.ipv4.flags,
             hdr.ipv4.frag_offset,
             hdr.ipv4.ttl,
             hdr.ipv4.protocol,
             hdr.ipv4.src_addr,
             hdr.ipv4.dst_addr});

        pkt.emit(hdr);
    }
}


Pipeline(SwitchIngressParser(),
    SwitchIngress(),
    SwitchIngressDeparser(),
    SwitchEgressParser(),
    SwitchEgress(),
    SwitchEgressDeparser()) pipe;

Switch(pipe) main;