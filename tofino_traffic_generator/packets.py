from scapy.layers.inet import IP, UDP, ICMP, TCP
from scapy.layers.l2 import Ether, Dot1Q
import codecs

# Some useful defines
IP_ETHERTYPE = 0x800
TCP_PROTOCOL = 0x6
UDP_PROTOCOL = 0x11

MINSIZE = 0
TEST_PARAMS = None
PORT_INFO = None


def ip_make_tos(tos, ecn, dscp):
    if ecn is not None:
        tos = (tos & ~(0x3)) | ecn
    if dscp is not None:
        tos = (tos & ~(0xFC)) | (dscp << 2)
    return tos


def simple_ip_packet(
    pktlen=100,
    eth_dst="00:01:02:03:04:05",
    eth_src="00:06:07:08:09:0a",
    dl_vlan_enable=False,
    vlan_vid=0,
    vlan_pcp=0,
    dl_vlan_cfi=0,
    ip_src="192.168.0.1",
    ip_dst="192.168.0.2",
    ip_tos=0,
    ip_ecn=None,
    ip_dscp=None,
    ip_ttl=64,
    ip_id=0x0001,
    ip_ihl=None,
    ip_options=False,
    ip_proto=0,
):
    if MINSIZE > pktlen:
        pktlen = MINSIZE

    ip_tos = ip_make_tos(ip_tos, ip_ecn, ip_dscp)

    # Note Dot1Q.id is really CFI
    if dl_vlan_enable:
        pkt = (
            Ether(dst=eth_dst, src=eth_src)
            / Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid)
            / IP(
                src=ip_src,
                dst=ip_dst,
                tos=ip_tos,
                ttl=ip_ttl,
                id=ip_id,
                ihl=ip_ihl,
                proto=ip_proto,
            )
        )
    else:
        if not ip_options:
            pkt = Ether(dst=eth_dst, src=eth_src) / IP(
                src=ip_src,
                dst=ip_dst,
                tos=ip_tos,
                ttl=ip_ttl,
                id=ip_id,
                ihl=ip_ihl,
                proto=ip_proto,
            )
        else:
            pkt = Ether(dst=eth_dst, src=eth_src) / IP(
                src=ip_src,
                dst=ip_dst,
                tos=ip_tos,
                ttl=ip_ttl,
                id=ip_id,
                ihl=ip_ihl,
                proto=ip_proto,
                options=ip_options,
            )

    pkt = pkt / codecs.decode(
        "".join(["%02x" % (x % 256) for x in range(pktlen - len(pkt))]), "hex"
    )

    return pkt


def simple_tcp_packet_ext_taglist(
    pktlen=100,
    eth_dst="00:01:02:03:04:05",
    eth_src="00:06:07:08:09:0a",
    dl_taglist_enable=False,
    dl_vlan_pcp_list=[0],
    dl_vlan_cfi_list=[0],
    dl_tpid_list=[0x8100],
    dl_vlanid_list=[1],
    ip_src="192.168.0.1",
    ip_dst="192.168.0.2",
    ip_tos=0,
    ip_ecn=None,
    ip_dscp=None,
    ip_ttl=64,
    ip_id=0x0001,
    ip_frag=0,
    ip_ihl=None,
    ip_options=False,
    tcp_sport=1234,
    tcp_dport=80,
    tcp_flags="S",
    payload=None,
    with_tcp_chksum=True,
):
    if MINSIZE > pktlen:
        pktlen = MINSIZE

    if with_tcp_chksum:
        tcp_hdr = TCP(sport=tcp_sport, dport=tcp_dport, flags=tcp_flags)
    else:
        tcp_hdr = TCP(sport=tcp_sport, dport=tcp_dport, flags=tcp_flags, chksum=0)

    ip_tos = ip_make_tos(ip_tos, ip_ecn, ip_dscp)

    # Note Dot1Q.id is really CFI
    if dl_taglist_enable:
        pkt = Ether(dst=eth_dst, src=eth_src)

        for i in range(0, len(dl_vlanid_list)):
            pkt = pkt / Dot1Q(
                prio=dl_vlan_pcp_list[i], id=dl_vlan_cfi_list[i], vlan=dl_vlanid_list[i]
            )

        pkt = (
            pkt
            / IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl)
            / tcp_hdr
        )

        for i in range(1, len(dl_tpid_list)):
            pkt[Dot1Q:i].type = dl_tpid_list[i]
        pkt.type = dl_tpid_list[0]

    else:
        if not ip_options:
            pkt = (
                Ether(dst=eth_dst, src=eth_src)
                / IP(
                    src=ip_src,
                    dst=ip_dst,
                    tos=ip_tos,
                    ttl=ip_ttl,
                    id=ip_id,
                    ihl=ip_ihl,
                    frag=ip_frag,
                )
                / tcp_hdr
            )
        else:
            pkt = (
                Ether(dst=eth_dst, src=eth_src)
                / IP(
                    src=ip_src,
                    dst=ip_dst,
                    tos=ip_tos,
                    ttl=ip_ttl,
                    id=ip_id,
                    ihl=ip_ihl,
                    frag=ip_frag,
                    options=ip_options,
                )
                / tcp_hdr
            )
    if payload:
        pkt = pkt / payload
    pkt = pkt / codecs.decode(
        "".join(["%02x" % (x % 256) for x in range(pktlen - len(pkt))]), "hex"
    )
    return pkt


def simple_tcp_packet(
    pktlen=100,
    eth_dst="00:01:02:03:04:05",
    eth_src="00:06:07:08:09:0a",
    dl_vlan_enable=False,
    vlan_vid=0,
    vlan_pcp=0,
    dl_vlan_cfi=0,
    ip_src="192.168.0.1",
    ip_dst="192.168.0.2",
    ip_tos=0,
    ip_ecn=None,
    ip_dscp=None,
    ip_ttl=64,
    ip_id=0x0001,
    ip_frag=0,
    ip_ihl=None,
    ip_options=False,
    tcp_sport=1234,
    tcp_dport=80,
    tcp_flags="S",
    payload=None,
    with_tcp_chksum=True,
):
    pcp_list = []
    cfi_list = []
    tpid_list = []
    vlan_list = []

    if dl_vlan_enable:
        pcp_list.append(vlan_pcp)
        cfi_list.append(dl_vlan_cfi)
        tpid_list.append(0x8100)
        vlan_list.append(vlan_vid)

    pkt = simple_tcp_packet_ext_taglist(
        pktlen=pktlen,
        eth_dst=eth_dst,
        eth_src=eth_src,
        dl_taglist_enable=dl_vlan_enable,
        dl_vlan_pcp_list=pcp_list,
        dl_vlan_cfi_list=cfi_list,
        dl_tpid_list=tpid_list,
        dl_vlanid_list=vlan_list,
        ip_src=ip_src,
        ip_dst=ip_dst,
        ip_tos=ip_tos,
        ip_ecn=ip_ecn,
        ip_dscp=ip_dscp,
        ip_ttl=ip_ttl,
        ip_id=ip_id,
        ip_frag=ip_frag,
        tcp_sport=tcp_sport,
        tcp_dport=tcp_dport,
        tcp_flags=tcp_flags,
        ip_ihl=ip_ihl,
        ip_options=ip_options,
        payload=payload,
        with_tcp_chksum=with_tcp_chksum,
    )
    return pkt


def simple_ipv4ip_packet(
    pktlen=300,
    eth_dst="00:01:02:03:04:05",
    eth_src="00:06:07:08:09:0a",
    dl_vlan_enable=False,
    vlan_vid=0,
    vlan_pcp=0,
    dl_vlan_cfi=0,
    ip_src="192.168.0.1",
    ip_dst="192.168.0.2",
    ip_tos=0,
    ip_ecn=None,
    ip_dscp=None,
    ip_ttl=64,
    ip_id=0x0001,
    ip_flags=0x0,
    ip_ihl=None,
    ip_options=False,
    inner_frame=None,
):
    if MINSIZE > pktlen:
        pktlen = MINSIZE

    ip_tos = ip_make_tos(ip_tos, ip_ecn, ip_dscp)

    # Note Dot1Q.id is really CFI
    if dl_vlan_enable:
        pkt = (
            Ether(dst=eth_dst, src=eth_src)
            / Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid)
            / IP(
                src=ip_src,
                dst=ip_dst,
                tos=ip_tos,
                ttl=ip_ttl,
                id=ip_id,
                flags=ip_flags,
                ihl=ip_ihl,
            )
        )
    else:
        if not ip_options:
            pkt = Ether(dst=eth_dst, src=eth_src) / IP(
                src=ip_src,
                dst=ip_dst,
                tos=ip_tos,
                ttl=ip_ttl,
                id=ip_id,
                flags=ip_flags,
                ihl=ip_ihl,
            )
        else:
            pkt = Ether(dst=eth_dst, src=eth_src) / IP(
                src=ip_src,
                dst=ip_dst,
                tos=ip_tos,
                ttl=ip_ttl,
                id=ip_id,
                flags=ip_flags,
                ihl=ip_ihl,
                options=ip_options,
            )

    if inner_frame:
        pkt = pkt / inner_frame
        inner_frame_bytes = bytearray(bytes(inner_frame))
        if (inner_frame_bytes[0] & 0xF0) == 0x40:
            pkt["IP"].proto = 4
        elif (inner_frame_bytes[0] & 0xF0) == 0x60:
            pkt["IP"].proto = 41
    else:
        pkt = pkt / IP()
        pkt = pkt / ("D" * (pktlen - len(pkt)))
        pkt["IP"].proto = 4

    return pkt


def simple_udp_packet(
    pktlen=100,
    eth_dst="00:01:02:03:04:05",
    eth_src="00:06:07:08:09:0a",
    dl_vlan_enable=False,
    vlan_vid=0,
    vlan_pcp=0,
    dl_vlan_cfi=0,
    ip_src="192.168.0.1",
    ip_dst="192.168.0.2",
    ip_tos=0,
    ip_ecn=None,
    ip_dscp=None,
    ip_ttl=64,
    ip_id=1,
    ip_ihl=None,
    ip_options=False,
    ip_flag=0,
    udp_sport=1234,
    udp_dport=80,
    udp_payload=None,
    with_udp_chksum=True,
):
    if MINSIZE > pktlen:
        pktlen = MINSIZE

    if with_udp_chksum:
        udp_hdr = UDP(sport=udp_sport, dport=udp_dport)
    else:
        udp_hdr = UDP(sport=udp_sport, dport=udp_dport, chksum=0)

    ip_tos = ip_make_tos(ip_tos, ip_ecn, ip_dscp)

    # Note Dot1Q.id is really CFI
    if dl_vlan_enable:
        pkt = (
            Ether(dst=eth_dst, src=eth_src)
            / Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid)
            / IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, ihl=ip_ihl, id=ip_id)
            / udp_hdr
        )
    else:
        if not ip_options:
            pkt = (
                Ether(dst=eth_dst, src=eth_src)
                / IP(
                    src=ip_src,
                    dst=ip_dst,
                    tos=ip_tos,
                    ttl=ip_ttl,
                    ihl=ip_ihl,
                    id=ip_id,
                    flags=ip_flag,
                )
                / udp_hdr
            )
        else:
            pkt = (
                Ether(dst=eth_dst, src=eth_src)
                / IP(
                    src=ip_src,
                    dst=ip_dst,
                    tos=ip_tos,
                    ttl=ip_ttl,
                    ihl=ip_ihl,
                    options=ip_options,
                    id=ip_id,
                    flags=ip_flag,
                )
                / udp_hdr
            )

    if udp_payload:
        pkt = pkt / udp_payload

    pkt = pkt / codecs.decode(
        "".join(["%02x" % (x % 256) for x in range(pktlen - len(pkt))]), "hex"
    )

    return pkt


def simple_icmp_packet(
    pktlen=60,
    eth_dst="00:01:02:03:04:05",
    eth_src="00:06:07:08:09:0a",
    dl_vlan_enable=False,
    vlan_vid=0,
    vlan_pcp=0,
    ip_src="192.168.0.1",
    ip_dst="192.168.0.2",
    ip_tos=0,
    ip_ecn=None,
    ip_dscp=None,
    ip_ttl=64,
    ip_id=1,
    icmp_type=8,
    icmp_code=0,
    icmp_data="",
):
    if MINSIZE > pktlen:
        pktlen = MINSIZE

    ip_tos = ip_make_tos(ip_tos, ip_ecn, ip_dscp)

    if dl_vlan_enable:
        pkt = (
            Ether(dst=eth_dst, src=eth_src)
            / Dot1Q(prio=vlan_pcp, id=0, vlan=vlan_vid)
            / IP(src=ip_src, dst=ip_dst, ttl=ip_ttl, tos=ip_tos, id=ip_id)
            / ICMP(type=icmp_type, code=icmp_code)
            / icmp_data
        )
    else:
        pkt = (
            Ether(dst=eth_dst, src=eth_src)
            / IP(src=ip_src, dst=ip_dst, ttl=ip_ttl, tos=ip_tos, id=ip_id)
            / ICMP(type=icmp_type, code=icmp_code)
            / icmp_data
        )

    pkt = pkt / ("0" * (pktlen - len(pkt)))

    return pkt
