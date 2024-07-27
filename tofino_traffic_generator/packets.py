from scapy.layers.inet import IP
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
    """
    Return a simple dataplane IP packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param eth_dst Destinatino MAC
    @param eth_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param vlan_vid VLAN ID
    @param vlan_pcp VLAN priority
    @param ip_src IP source
    @param ip_dst IP destination
    @param ip_tos IP ToS
    @param ip_ecn IP ToS ECN
    @param ip_dscp IP ToS DSCP
    @param ip_ttl IP TTL
    @param ip_id IP ID

    Generates a simple IP packet.  Users
    shouldn't assume anything about this packet other than that
    it is a valid ethernet/IP frame.
    """

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
