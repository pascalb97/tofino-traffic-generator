import os
import sys
from jinja2 import Environment, FileSystemLoader
import ipaddress

SOURCE_DIRECTORY = "src"


def delete_existing_files(source_files):
    for file in source_files:
        file_path = os.path.join(SOURCE_DIRECTORY, file)
        if os.path.exists(file_path):
            os.remove(file_path)


def template_to_file(template_file: str, target_file: str, template_data: dict):
    env = Environment(loader=FileSystemLoader("."))
    template = env.get_template(template_file)
    output = template.render(template_data)
    with open(target_file, "w") as file:
        file.write(output)
    print(f"[+] Generated {target_file}")


def initialize_src():
    if not os.path.exists(SOURCE_DIRECTORY):
        os.makedirs(SOURCE_DIRECTORY)
    source_files = [
        "headers.p4",
        "port_config.txt",
        "traffic_gen.p4",
    ]
    delete_existing_files(source_files)


def generate_p4(throughput_defined, throughput_mode, traffic_configurator):
    template_data = {
        "throughput_defined": throughput_defined,
        "throughput_mode": throughput_mode,
        "traffic_gen": traffic_configurator,
    }
    template_to_file(
        "templates/traffic_gen_template.p4.j2", "src/traffic_gen.p4", template_data
    )


def generate_header(header_list, eth_defined, IP_defined, udp_defined, tcp_defined):
    template_data = {
        "headers": header_list,
        "eth_defined": eth_defined,
        "IP_defined": IP_defined,
        "udp_defined": udp_defined,
        "tcp_defined": tcp_defined,
    }
    template_to_file(
        "templates/headers_template.p4.j2", "src/headers.p4", template_data
    )


def generate_port_config(port, port_bw):
    template_data = {"port": port, "port_bw": port_bw}
    template_to_file(
        "templates/port_config_template.txt.j2", "src/port_config.txt", template_data
    )


class Field:
    def __init__(self, name="", size=0, default_value=0):
        self.name = name  # name of the field
        self.size = size  # size in bits
        self.default_value = default_value  # default value for the field

        if name == "" or size == 0:
            print("[ERROR] The field needs a valid name and a size > 0")
            sys.exit()


class Header:
    def __init__(self, name=None, size=None):
        if name is None or size is None:
            raise ValueError("[ERROR] The header requires a valid name and a size > 0")
        if size % 8 != 0:
            raise ValueError("[ERROR] The header size needs to be byte aligned")

        self.name = name  # name of the header
        self.size = size  # header total_len
        self.fields = []  # list of all header fields

    def valid_header(self):
        if self.size <= 0 or len(self.fields) == 0:
            raise ValueError("[ERROR] Invalid header size")

        total_field_sizes = sum(field.size for field in self.fields)

        if total_field_sizes != self.size:
            raise ValueError(
                f"[ERROR] Header {self.name} has mismatching total field sizes"
            )

        return True

    @staticmethod
    def is_header_valid(header):
        try:
            return isinstance(header, Header) and header.valid_header()
        except ValueError:
            return False


class TrafficConfigurator:
    def __init__(self):
        # config params
        # self.name = name
        self.p4_code = ""
        self.generation_port = 68
        self.output_port = 0
        self.channel = 0
        self.port_bw = ""
        self.throughput_defined = False
        self.throughput = 0
        self.throughput_mode = ""  # meter or port_shaping
        self.pkt_len = 64

        # list of customized headers
        self.headers = []

        # header params
        self.version = 4
        self.ihl = 5
        self.tos = "0x0"
        self.len = None
        self.frag = 0
        self.flags = None
        self.ttl = 61
        self.proto = "udp"
        self.chksum = "0x66df"
        self.src = None
        self.dst = None
        self.hwsrc = None
        self.hwdst = None
        self.type = "Ipv4"
        self.data = None

        # defineds
        self.eth_defined = False
        self.IP_defined = False
        self.udp_defined = False
        self.tcp_defined = False

        # new params
        self.eth_dst = "00:01:02:03:04:05"
        self.eth_src = "00:06:07:08:09:0a"
        self.ip_src = "192.168.0.1"
        self.ip_dst = "192.168.0.2"
        self.source_mask = "255.255.255.255"
        self.destination_mask = "255.255.255.255"
        self.ip_proto = 0
        self.ip_tos = 0
        self.vlan_vid = 0
        self.vlan_pcp = 0
        self.dl_vlan_cfi = 0
        self.dl_vlan_enable = False
        self.ip_ecn = None
        self.ip_dscp = None
        self.ip_ttl = 64
        self.ip_id = 0x0001
        self.ip_ihl = None
        self.ip_options = False

    def get_attributes(self):
        attributes = dir(self)
        # Filter out the special methods (those starting and ending with __)
        attributes = [attr for attr in attributes if not attr.startswith("__")]
        return attributes

    def add_generation_port(self, port):
        self.generation_port = port

    def add_output_port(self, port, channel, bw):
        self.output_port = port
        self.channel = channel
        self.port_bw = bw

    def cidr_to_netmask(self, cidr):
        network = ipaddress.ip_network(cidr, strict=False)
        return str(network.netmask)

    def set_masks(self, source_cidr=None, destination_cidr=None):
        if source_cidr:
            self.source_mask = self.cidr_to_netmask(source_cidr)
        if destination_cidr:
            self.destination_mask = self.cidr_to_netmask(destination_cidr)

    def add_ip(
        self,
        pkt_len=100,
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
        @param pktlen Length of packet in bytes w/o CRC
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
        self.IP_defined = True

        self.pkt_len = pkt_len
        self.hwdst = eth_dst
        self.hwsrc = eth_src
        self.src = ip_src
        self.dst = ip_dst
        # self.ttl = ip_ttl
        # self.ihl = ip_ihl
        self.tos = ip_tos
        self.proto = ip_proto
        self.eth_dst = eth_dst
        self.eth_src = eth_src
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.ip_proto = ip_proto
        self.ip_tos = ip_tos
        self.vlan_vid = vlan_vid
        self.vlan_pcp = vlan_pcp
        self.dl_vlan_cfi = dl_vlan_cfi
        self.dl_vlan_enable = dl_vlan_enable
        self.ip_ecn = ip_ecn
        self.ip_dscp = ip_dscp
        self.ip_ttl = ip_ttl
        self.ip_id = ip_id
        self.ip_ihl = ip_ihl
        self.ip_options = ip_options

    def add_ethernet(self, hwsrc=None, hwdst=None, type="Ipv4", data=None):
        self.hwsrc = hwsrc
        self.hwdst = hwdst
        self.type = type
        self.data = data

    def add_throughput(self, throughput, mode):
        self.throughput_defined = True
        self.throughput = throughput
        self.throughput_mode = mode

    def add_header(self, header):
        if not isinstance(header, (Header, list)):
            raise TypeError("[ERROR] The supplied header is not of correct type!")

        headers_to_add = header if isinstance(header, list) else [header]

        invalid_headers = [
            hdr for hdr in headers_to_add if not header.is_header_valid(hdr)
        ]
        if invalid_headers:
            raise ValueError(
                f"[ERROR] The following headers are invalid: {invalid_headers}"
            )

        self.headers.extend(headers_to_add)

    def print_headers(self):
        if len(self.headers) != 0:
            print("[+] Customized headers defined:")
            for hdr in self.headers:
                hdr.printHeader()

    def generate(self):
        initialize_src()
        if (
            not self.eth_defined
            and not self.IP_defined
            and not self.udp_defined
            and not self.tcp_defined
        ):
            self.eth_defined = True
        generate_p4(self.throughput_defined, self.throughput_mode, self)
        generate_header(
            self.headers,
            self.eth_defined,
            self.IP_defined,
            self.udp_defined,
            self.tcp_defined,
        )
        generate_port_config(self.output_port, self.port_bw)
        self.print_headers()
