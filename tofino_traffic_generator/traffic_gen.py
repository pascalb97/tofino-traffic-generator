#!/usr/bin/env python
import sys
import os
import time
import struct
import socket
import signal
import json

# sys.path.append(os.path.expandvars("$SDE/install/lib/python3.8/site-packages/tofino/"))
# sys.path.append(os.path.expandvars("$SDE/install/lib/python3.8/site-packages/"))
# sys.path.append(os.path.expandvars("$SDE/install/lib/python3.8/site-packages/ptf/"))

import grpc

# import testutils

from queue import Queue
from queue import Empty
from threading import Thread

import bfrt_helper.pb2.bfruntime_pb2 as bfruntime_pb2
import bfrt_helper.pb2.bfruntime_pb2_grpc as bfruntime_pb2_grpc
from bfrt_helper.bfrt import BfRtHelper
from bfrt_helper.bfrt_info import BfRtInfo
from ssh_conn import ssh_conn
from tofino_traffic_gen.ssh_conn import remote_file_read, ssh_exec

# DEVICE_ID = 0
# CLIENT_ID = 0

# HOME = os.getenv("HOME", None)
# SDE_INSTALL = os.getenv("SDE_INSTALL", None)

# PROGRAM_NAME = "traffic_gen"
# BFRT_PATH = f"{SDE_INSTALL}/share/tofinopd/{PROGRAM_NAME}/bf-rt.json"
# CTX_PATH = f"{SDE_INSTALL}/share/tofinopd/{PROGRAM_NAME}/pipe/context.json"
# BIN_PATH = f"{SDE_INSTALL}/share/tofinopd/{PROGRAM_NAME}/pipe/tofino.bin"


def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def mac2int(mac_str):
    return int(mac_str.replace(":", ""), 16)


def stream_req_iterator():
    while True:
        p = stream_out_queue.get()
        if p is None:
            break
        print("Stream sending: ", p)
        yield p


def stream_recv(stream):
    try:
        for p in stream:
            print("Stream received: ", p)
            stream_in_queue.put(p)
    except Exception as e:
        print(str(e))


def close(sig, frame):
    stream_out_queue.put(None)
    stream_recv_thread.join()


def close_grpc_connection(sig, frame):
    stream_out_queue.put(None)
    stream_recv_thread.join()


def get_remote_env_vars(ssh_client, var_names):
    env_vars = {}
    try:
        for var_name in var_names:
            stdin, stdout, stderr = ssh_exec(
                ssh_client, f". .profile ; echo ${var_name}"
            )
            error_message = stderr.read().decode("ascii").strip()
            if error_message:
                raise Exception(
                    f"Error occurred while executing command for {var_name}:"
                    f" {error_message}"
                )
            result = stdout.read().decode("ascii").strip("\n")
            if not result:
                raise ValueError(
                    f"Environment variable '{var_name}' not found or empty."
                )
            env_vars[var_name] = result
        return env_vars
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def get_bfrt_definition(
    program_name, remote_env_vars=None, local=True, ssh_client=None
):
    if local == True:
        file_path = (
            f'{os.getenv("SDE_INSTALL")}/share/tofinopd/{program_name}/bf-rt.json'
        )
        return json.loads(open(file_path).read())
    else:
        bfsde_install_path = remote_env_vars["SDE_INSTALL"]
        file_path = f"{bfsde_install_path}/share/tofinopd/{program_name}/bf-rt.json"
        bfrt_json = remote_file_read(ssh_client, file_path)
        return json.loads(bfrt_json)


def connect_to_bfrt(
    program_name,
    host="127.0.0.1",
    port="50052",
    device_id=0,
    client_id=0,
    local=True,
    ssh_client=None,
):
    if not local and ssh_client is None:
        raise ValueError("SSH client is required for remote connection")
    if local:
        ssh_client = ssh_conn(
            hostname=hostname, username=username, keyfile=keyfile, port=ssh_port
        )
        bfsde_env_vars = get_remote_env_vars(ssh_client, ["SDE_INSTALL", "SDE"])
        bfrt_data = get_bfrt_definition(
            program_name=program_name,
            remote_env_vars=bfsde_env_vars,
            local=local,
            ssh_client=ssh_client,
        )
    else:
        bfrt_data = get_bfrt_definition(program_name)

    channel = grpc.insecure_channel(f"{host}:{port}")
    client = bfruntime_pb2_grpc.BfRuntimeStub(channel)
    stream_out_queue = Queue()  # Stream request channel (self._stream),
    stream_in_queue = Queue()  # Receiving messages from device
    stream = client.StreamChannel(stream_req_iterator())
    stream_recv_thread = Thread(target=stream_recv, args=(stream,))
    stream_recv_thread.start()
    signal.signal(signal.SIGINT, close)

    brft_info = BfRtInfo(bfrt_data)
    bfrt_helper = BfRtHelper(device_id, client_id, brft_info)
    return bfrt_helper.create_subscribe_request(), stream_out_queue, stream_in_queue


def clear_table(
    program_name, bfrt_helper, table_name, stream_out_queue, stream_in_queue
):
    request = bfrt_helper.create_subscribe_request()
    stream_out_queue.put(request)
    stream_in_queue.get()
    table = bfrt_info.get_table(table_name)
    if table is None:
        print(f"Table {table_name} not found")
        return
    for key in table.key:
        if key is not None:
            print(key)
            """
            request = bfrt__helper.create_table_write(
                program_name, table_name, key, None
            )
            """


hostname = "gf9db44"
username = "vagrant"
progam_name = "traffic_gen"
grpc_port = "50053"
keyfile = "/Users/pascal/.ssh/tofinovm_key"
ssh_port = 2222

ssh_client = ssh_conn(
    hostname=hostname, username=username, keyfile=keyfile, port=ssh_port
)
bfrt_helper, stream_out_queue, stream_in_queue = connect_to_bfrt(
    program_name="traffic_gen",
    host=hostname,
    port=grpc_port,
    client_id=0,
    device_id=0,
    local=False,
    ssh_client=ssh_client,
)

clear_table(
    "traffic_gen",
    bfrt_helper,
    "pipe.SwitchEgress.egress_table",
    stream_out_queue,
    stream_in_queue,
)


"""
# Connect to BF Runtime Server
interface = gc.ClientInterface(grpc_addr="localhost:50052", client_id=0, device_id=0)
print("Connected to BF Runtime Server")

# Get the information about the running program on the bfrt server.
bfrt_info = interface.bfrt_info_get()
print("The target runs program ", bfrt_info.p4_name_get())

# Establish that you are working with this program
interface.bind_pipeline_config(bfrt_info.p4_name_get())

####### You can now use BFRT CLIENT #######
target = gc.Target(device_id=0, pipe_id=0xFFFF)
t_cfg_table = bfrt_info.table_get("$mirror.cfg")
t_fwd_table = bfrt_info.table_get("t")

# ####### t_table ########
print("clean timer table")
resp = t_fwd_table.entry_get(target, [], {"from_hw": True})
for _, key in resp:
    if key:
        t_fwd_table.entry_del(target, [key])

print("configure timer table")
i_port = 68  # Default port for pktgen
pipe_id = 0
g_timer_app_id = 1
batch_id = [0, 1, 2, 3]  # 0, 1, 2, 3
packet_id = [0, 1]  # 0, 1
o_port = 1  # HW port to send the packets

th = 3000000
p_shaping = bfrt_info.table_get("tf1.tm.port.sched_cfg")
p_shaping2 = bfrt_info.table_get("tf1.tm.port.sched_shaping")
p_shaping.entry_mod(
    target,
    [p_shaping.make_key([gc.KeyTuple("dev_port", 1)])],
    [p_shaping.make_data([gc.DataTuple("max_rate_enable", bool_val=True)])],
)
p_shaping2.entry_mod(
    target,
    [p_shaping2.make_key([gc.KeyTuple("dev_port", 1)])],
    [
        p_shaping2.make_data(
            [
                gc.DataTuple("unit", str_val="BPS"),
                gc.DataTuple("provisioning", str_val="MIN_ERROR"),
                gc.DataTuple("max_rate", th),
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
    [t_fwd_table.make_data([gc.DataTuple("port", o_port)], "SwitchIngress.match")],
)

pktgen_app_cfg_table = bfrt_info.table_get("app_cfg")
pktgen_pkt_buffer_table = bfrt_info.table_get("pkt_buffer")
pktgen_port_cfg_table = bfrt_info.table_get("port_cfg")

app_id = g_timer_app_id
pktlen = 64
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
    ip_proto=0,
)

p.show()

table = bfrt_info.table_get("pipe.SwitchEgress.egress_table")
table.entry_del(target)

print(ip2int(s_mask))
print(ip2int(d_mask))

table.entry_add(
    target,
    [table.make_key([gc.KeyTuple("eg_intr_md.egress_port", o_port)])],
    [
        table.make_data(
            [
                gc.DataTuple("src_mac", mac2int(eth_src)),
                gc.DataTuple("dst_mac", mac2int(eth_dst)),
                gc.DataTuple("s_mask", ip2int(s_mask)),
                gc.DataTuple("d_mask", ip2int(d_mask)),
                gc.DataTuple("s_ip", ip2int(ip_src)),
                gc.DataTuple("d_ip", ip2int(ip_dst)),
                gc.DataTuple("tos", ip_tos),
            ],
            "SwitchEgress.replace_ip_address",
        )
    ],
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
"""
