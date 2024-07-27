#!/usr/bin/env python
import sys
import os
import time
import struct
import socket
sys.path.append(os.path.expandvars('$SDE/install/lib/python3.8/site-packages/tofino/'))
sys.path.append(os.path.expandvars('$SDE/install/lib/python3.8/site-packages/'))
sys.path.append(os.path.expandvars('$SDE/install/lib/python3.8/site-packages/ptf/'))
import grpc
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as gc

import testutils


def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def mac2int(mac_str):
    return int(mac_str.replace(":", ""), 16)

# Connect to BF Runtime Server
interface = gc.ClientInterface(
    grpc_addr="localhost:50052",
    client_id=0,
    device_id=0
)
print('Connected to BF Runtime Server')

# Get the information about the running program on the bfrt server.
bfrt_info = interface.bfrt_info_get()
print('The target runs program ', bfrt_info.p4_name_get())

# Establish that you are working with this program
interface.bind_pipeline_config(bfrt_info.p4_name_get())

# create target definition
target = gc.Target(device_id=0, pipe_id=0xffff)
t_cfg_table = bfrt_info.table_get("$mirror.cfg")
t_fwd_table = bfrt_info.table_get("t")

# reset timer table
print("clean timer table")
resp = t_fwd_table.entry_get(target, [], {"from_hw": True})
for _, key in resp:
    if key:
        t_fwd_table.entry_del(target, [key])

print("configure timer table")
generation_port = 68  # Default port for pktgen
pipe_id = 0
g_timer_app_id = 1
batch_id = [0, 1, 2, 3]  # 0, 1, 2, 3
packet_id = [0, 1]  # 0, 1
output_port = 5  # HW port to send the packets

th = 3000000
p_shaping = bfrt_info.table_get("tf1.tm.port.sched_cfg")
p_shaping2 = bfrt_info.table_get("tf1.tm.port.sched_shaping")
p_shaping.entry_mod(
    target,
    [p_shaping.make_key([gc.KeyTuple("dev_port", 5)])],
    [p_shaping.make_data([gc.DataTuple("max_rate_enable", bool_val=True)])],
)
p_shaping2.entry_mod(
    target,
    [p_shaping2.make_key([gc.KeyTuple("dev_port", 5)])],
    [
        p_shaping2.make_data(
            [
                gc.DataTuple("unit", str_val="BPS"),
                gc.DataTuple("provisioning", str_val="MIN_ERROR"),
                gc.DataTuple("max_rate", throughput),
                gc.DataTuple("max_burst_size", 1000),
            ]
        )
    ],
)
t_fwd_table.entry_add(
    target,
    [
        t_fwd_table.make_key(
            [
                gc.KeyTuple("ig_intr_md.ingress_port", i_port),
                gc.KeyTuple("hdr.timer.pipe_id", pipe_id),
                gc.KeyTuple("hdr.timer.app_id", g_timer_app_id),
                gc.KeyTuple("hdr.timer.batch_id", batch_id[0]),
                gc.KeyTuple("hdr.timer.packet_id", packet_id[0]),
            ]
        )
    ],
    [t_fwd_table.make_data([gc.DataTuple("port", output_port)], "SwitchIngress.match")],
)

pktgen_app_cfg_table = bfrt_info.table_get("app_cfg")
pktgen_pkt_buffer_table = bfrt_info.table_get("pkt_buffer")
pktgen_port_cfg_table = bfrt_info.table_get("port_cfg")

app_id = g_timer_app_id
pktlen = 100
pgen_pipe_id = 0
src_port = 68
p_count = 1  # packets per batch
b_count = 1  # batch number
buff_offset = 144  # generated packets' payload will be taken from the offset in buffer

# build expected generated packets
print("Create packet")

eth_dst = "00:01:02:03:04:05"
eth_src = "00:06:07:08:09:0a"
ip_src = "10.2.2.1"
ip_dst = "10.2.2.2"
s_mask = "255.255.255.255"
d_mask = "255.255.255.0"
ip_tos = 0

p = testutils.simple_ip_packet(
    pktlen=pktlen,
    eth_dst="00:01:02:03:04:05",
    eth_src="00:06:07:08:09:0a",
    dl_vlan_enable=False,
    vlan_vid=0,
    vlan_pcp=0,
    dl_vlan_cfi=0,
    ip_src="10.2.2.1",
    ip_dst="10.2.2.2",
    ip_tos=0,
    ip_ecn=None,
    ip_dscp=None,
    ip_ttl=64,
    ip_id=1,
    ip_ihl=None,
    ip_options=False,
    ip_proto=0
)

p.show()

table = bfrt_info.table_get("pipe.SwitchEgress.egress_table")
table.entry_del(target)

table.entry_add(
    target,
    [table.make_key([gc.KeyTuple('eg_intr_md.egress_port', output_port)])],
    [
        table.make_data(
            [
                gc.DataTuple('src_mac', mac2int(eth_src)),
                gc.DataTuple('dst_mac', mac2int(eth_dst)),
                gc.DataTuple('s_mask', ip2int(s_mask)),
                gc.DataTuple('d_mask', ip2int(d_mask)),
                gc.DataTuple('s_ip', ip2int(ip_src)),
                gc.DataTuple('d_ip', ip2int(ip_dst)),
                gc.DataTuple('tos', ip_tos),
            ],
            'SwitchEgress.replace_ip_address'
        )
    ]
)

# p = testutils.simple_eth_packet(pktlen=1024)

print("enable pktgen port")

pktgen_port_cfg_table.entry_add(
    target,
    [pktgen_port_cfg_table.make_key([gc.KeyTuple("dev_port", src_port)])],
    [pktgen_port_cfg_table.make_data([gc.DataTuple("pktgen_enable", bool_val=True)])],
)

# Configure the packet generation timer application
print("configure pktgen application")
data = pktgen_app_cfg_table.make_data(
    [
        gc.DataTuple("timer_nanosec", 1),
        gc.DataTuple("app_enable", bool_val=False),
        gc.DataTuple("pkt_len", (pktlen - 6)),
        gc.DataTuple("pkt_buffer_offset", buff_offset),
        gc.DataTuple("pipe_local_source_port", src_port),
        gc.DataTuple("increment_source_port", bool_val=False),
        gc.DataTuple("batch_count_cfg", b_count - 1),
        gc.DataTuple("packets_per_batch_cfg", p_count - 1),
        gc.DataTuple("ibg", 0),
        gc.DataTuple("ibg_jitter", 0),
        gc.DataTuple("ipg", 0),
        gc.DataTuple("ipg_jitter", 0),
        gc.DataTuple("batch_counter", 0),
        gc.DataTuple("pkt_counter", 0),
        gc.DataTuple("trigger_counter", 0),
    ],
    "trigger_timer_periodic",
)

offset = 0
offset += pktlen - 2
if offset % 16 != 0:
    offset += 16 - (offset % 16)

print(f"Offset: {offset}")
print(f"Buffer Offset: {pktlen+offset}")

pktgen_app_cfg_table.entry_mod(
    target,
    [pktgen_app_cfg_table.make_key([gc.KeyTuple("app_id", g_timer_app_id)])],
    [data],
)

print("configure packet buffer")
print(dir(pktgen_pkt_buffer_table))
print(pktgen_pkt_buffer_table.info)
pktgen_pkt_buffer_table.entry_mod(
    target,
    [
        pktgen_pkt_buffer_table.make_key(
            [
                gc.KeyTuple("pkt_buffer_offset", buff_offset),
                gc.KeyTuple("pkt_buffer_size", (pktlen - 6)),
            ]
        )
    ],
    [
        pktgen_pkt_buffer_table.make_data(
            [gc.DataTuple("buffer", bytearray(bytes(p)[6:]))]
        )
    ],
)

print("enable pktgen")
pktgen_app_cfg_table.entry_mod(
    target,
    [pktgen_app_cfg_table.make_key([gc.KeyTuple("app_id", g_timer_app_id)])],
    [
        pktgen_app_cfg_table.make_data(
            [gc.DataTuple("app_enable", bool_val=True)], "trigger_timer_periodic"
        )
    ],
)

# Test the follwing code, add parameters in config function

time.sleep(4)

print("disable pktgen")
pktgen_app_cfg_table.entry_mod(
    target,
    [pktgen_app_cfg_table.make_key([gc.KeyTuple("app_id", g_timer_app_id)])],
    [
        pktgen_app_cfg_table.make_data(
            [gc.DataTuple("app_enable", bool_val=False)], "trigger_timer_one_shot"
        )
    ],
)