/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "polka.p4h"

parser MyParser(
    packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    state start {
        meta.apply_sr = 0;
        transition verify_ethernet;
    }

    state verify_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ethertype) {
            TYPE_POLKA: get_polka_header;
            // Should be dropped when apply_sr is 0
            // But can't use drop here on BMV2
            default: accept;
        }
    }

    state get_polka_header {
        meta.apply_sr = 1;
        packet.extract(hdr.polka);
        meta.routeid = hdr.polka.routeid;

        transition select(hdr.polka.version) {
            PROBE_VERSION: parse_polka_probe;
            // Any other packet
            default: accept;
        }
    }

    state parse_polka_probe {
        packet.extract(hdr.polka_probe);
        transition accept;
    }

}

control MyVerifyChecksum(
    inout headers hdr,
    inout metadata meta
) {
    apply {  }
}

control MySignPacket(
    inout headers hdr,
    inout metadata meta
) {
    // Signs the packet
    // TODO: include switchid - currently only hashing
    apply {
        hdr.polka_probe.setValid();

        // At this point, `meta.port` should be written on already
        hdr.polka_probe.l_hash = (bit<32>) meta.port ^ hdr.polka_probe.l_hash;

        bit<16> nbase = 0;
        bit<32> min_bound = 0;
        bit<32> max_bound = 0xFFFFFFFF;
        hash(
            hdr.polka_probe.l_hash,
            HashAlgorithm.crc32,
            min_bound,
            {hdr.polka_probe.l_hash},
            max_bound
        );
    }
}

control MyIngress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    // Calculates the next hop (port) based on the routeid
    action srcRoute_nhop() {
        // routeId % switchId = portId
        
        bit<160> ndata = meta.routeid >> 16;
        bit<16> dif = (bit<16>) (meta.routeid ^ (ndata << 16));

        bit<16> nresult;
        bit<64> ncount = 4294967296 * 2;
        bit<16> nbase = 0;
        hash(
            nresult,
            HashAlgorithm.crc16_custom,
            nbase,
            {ndata},
            ncount
        );

        bit<16> nport = nresult ^ dif;

        // TODO probably doesn't need helper metadata field, acessing standard_metadata.egress_spec directly
        meta.port = (bit<9>) nport;
        standard_metadata.egress_spec = meta.port;
    }

    apply {
        if (meta.apply_sr == 0) {
            mark_to_drop(standard_metadata);
        } else {
            srcRoute_nhop();
            standard_metadata.egress_spec = meta.port;
            if (hdr.polka.version == PROBE_VERSION) {
                MySignPacket.apply(hdr, meta);
            } else {
                hdr.polka_probe.setInvalid();
            }
        }
    }
}

control MyEgress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    apply { 
        // Packet isn't leaving the core
     }
}

control MyComputeChecksum(
    inout headers hdr,
    inout metadata meta
) {
    apply {
        // No checksum currently being calculated
    }
}

control MyDeparser(
    packet_out packet,
    in headers hdr
) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.polka);
        packet.emit(hdr.polka_probe);
        packet.emit(hdr.ipv4);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
