import os
import sys
from jinja2 import Environment, FileSystemLoader
import ipaddress
import packets

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


def generate_header(eth_defined, IP_defined, udp_defined, tcp_defined):
    template_data = {
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


class TrafficConfigurator:
    def __init__(self, virtual_switch=True):
        # config params
        # self.name = name
        self.virtual_switch = virtual_switch
        self.p4_code = ""
        self.output_physical_port = 1
        self.output_virtual_port = 1
        self.channel = 0
        self.port_speed = ""
        self.throughput_defined = False
        self.throughput = 3000
        self.throughput_mode = ""  # meter or port_shaping
        self.pkt_len = 64

        # packet generator options
        self.generation_port = 68
        self.generation_time_s = 5
        self.g_timer_app_id = 1
        self.packet_batch_size = 1  # packets per batch
        self.packet_batch_number = 1  # batch number
        self.packet_buffer_offset = (
            144  # generated packets' payload will be taken from the offset in buffer
        )

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
        self.ip_flags = 0x0
        self.ip_frag = 0
        self.ip_ihl = None
        self.ip_options = False
        self.packet = packets.simple_ip_packet()

    def craft_ipv4_packet(self, payload=None):
        self.packet = packets.simple_ipv4ip_packet(
            pktlen=self.pkt_len,
            eth_dst=self.eth_dst,
            eth_src=self.eth_src,
            dl_vlan_enable=self.dl_vlan_enable,
            vlan_vid=self.vlan_vid,
            vlan_pcp=self.vlan_pcp,
            dl_vlan_cfi=self.dl_vlan_cfi,
            ip_src=self.ip_src,
            ip_dst=self.ip_dst,
            ip_tos=self.ip_tos,
            ip_ecn=self.ip_ecn,
            ip_dscp=self.ip_dscp,
            ip_ttl=self.ip_ttl,
            ip_id=self.ip_id,
            ip_flags=self.ip_flags,
            ip_ihl=self.ip_ihl,
            ip_options=self.ip_options,
            inner_frame=payload,
        )

    def craft_tcp_packet(
        self,
        source_port=1234,
        dest_port=80,
        tcp_flags="S",
        payload=None,
        with_checksum=True,
    ):
        self.packet = packets.simple_tcp_packet(
            pktlen=self.pkt_len,
            eth_dst=self.eth_dst,
            eth_src=self.eth_src,
            dl_vlan_enable=self.dl_vlan_enable,
            vlan_vid=self.vlan_vid,
            vlan_pcp=self.vlan_pcp,
            dl_vlan_cfi=self.dl_vlan_cfi,
            ip_src=self.ip_src,
            ip_dst=self.ip_dst,
            ip_tos=self.ip_tos,
            ip_ecn=self.ip_ecn,
            ip_dscp=self.ip_dscp,
            ip_ttl=self.ip_ttl,
            ip_id=self.ip_id,
            ip_frag=self.ip_frag,
            ip_ihl=self.ip_ihl,
            ip_options=self.ip_options,
            tcp_sport=source_port,
            tcp_dport=dest_port,
            tcp_flags=tcp_flags,
            payload=payload,
            with_tcp_chksum=with_checksum,
        )

    def craft_udp_packet(
        self, source_port=1234, dest_port=80, payload=None, with_checksum=True
    ):
        self.packet = packets.simple_udp_packet(
            pktlen=self.pkt_len,
            eth_dst=self.eth_dst,
            eth_src=self.eth_src,
            dl_vlan_enable=self.dl_vlan_enable,
            vlan_vid=self.vlan_vid,
            vlan_pcp=self.vlan_pcp,
            dl_vlan_cfi=self.dl_vlan_cfi,
            ip_src=self.ip_src,
            ip_dst=self.ip_dst,
            ip_tos=self.ip_tos,
            ip_ecn=self.ip_ecn,
            ip_dscp=self.ip_dscp,
            ip_ttl=self.ip_ttl,
            ip_id=self.ip_id,
            ip_ihl=self.ip_ihl,
            ip_options=self.ip_options,
            ip_flag=self.ip_flags,
            udp_sport=source_port,
            udp_dport=dest_port,
            udp_payload=payload,
            with_udp_chksum=with_checksum,
        )

    def get_attributes(self):
        attributes = dir(self)
        # Filter out the special methods (those starting and ending with __)
        attributes = [attr for attr in attributes if not attr.startswith("__")]
        return attributes

    def configure_generator(
        self,
        port=68,
        generation_time_s=5,
        timer_app_id=1,
        packet_batch_size=1,
        packet_batch_number=1,
        packet_buffer_offset=144,
    ):
        self.generation_port = port
        self.generation_time_s = generation_time_s
        self.g_timer_app_id = timer_app_id
        self.packet_batch_size = packet_batch_size  # packets per batch
        self.packet_batch_number = packet_batch_number  # batch number
        self.packet_buffer_offset = packet_buffer_offset

    def add_physical_output_port(self, output_physical_port, port_speed):
        self.output_physical_port = output_physical_port
        self.port_speed = port_speed

    def add_virtual_output_port(self, output_virtual_port):
        self.output_virtual_port = output_virtual_port

    def cidr_to_netmask(self, cidr):
        network = ipaddress.ip_network(cidr, strict=False)
        return str(network.netmask)

    def add_packet_data(
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
        source_cidr=None,
        destination_cidr=None,
        ip_tos=0,
        ip_ecn=None,
        ip_dscp=None,
        ip_ttl=64,
        ip_id=0x0001,
        ip_ihl=None,
        ip_frag=0,
        ip_options=False,
        ip_proto=0,
        ip_flag=0,
    ):
        self.IP_defined = True

        self.pkt_len = pkt_len
        self.hwdst = eth_dst
        self.hwsrc = eth_src
        self.src = ip_src
        self.dst = ip_dst
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
        self.ip_flag = ip_flag
        self.ip_id = ip_id
        self.ip_ihl = ip_ihl
        self.ip_frag = ip_frag
        self.ip_options = ip_options

        if source_cidr:
            self.ip_src, self.source_mask = source_cidr.split("/")
            self.source_mask = self.cidr_to_netmask(source_cidr)
        else:
            self.ip_src = ip_src
            self.source_mask = None

        if destination_cidr:
            self.ip_dst, self.destination_mask = destination_cidr.split("/")
            self.destination_mask = self.cidr_to_netmask(destination_cidr)
        else:
            self.ip_dst = ip_dst
            self.destination_mask = None

    def add_throughput(self, throughput, mode):
        self.throughput_defined = True
        self.throughput = throughput
        self.throughput_mode = mode

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
            self.eth_defined,
            self.IP_defined,
            self.udp_defined,
            self.tcp_defined,
        )
        generate_port_config(self.output_physical_port, self.port_speed)
