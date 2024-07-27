import os
from packets import simple_ip_packet
from ssh_conn import ssh_conn
from switch_controller import TofinoSwitch, TrafficGenerator, GRPCManager
from traffic_config import TrafficConfigurator
from bfrt_helper.fields import DevPort, PortId
from bfrt_helper.match import Exact

# import logging


# sys.path.append(os.path.expandvars("$SDE/install/lib/python3.8/site-packages/tofino/"))
# sys.path.append(os.path.expandvars("$SDE/install/lib/python3.8/site-packages/"))
# sys.path.append(os.path.expandvars("$SDE/install/lib/python3.8/site-packages/ptf/"))


# BFRT_PATH = f"{SDE_INSTALL}/share/tofinopd/{PROGRAM_NAME}/bf-rt.json"
# CTX_PATH = f"{SDE_INSTALL}/share/tofinopd/{PROGRAM_NAME}/pipe/context.json"
# BIN_PATH = f"{SDE_INSTALL}/share/tofinopd/{PROGRAM_NAME}/pipe/tofino.bin"

ENV_VAR_NOT_FOUND_ERROR = "Environment variable '{}' not found or empty."
COMMAND_EXECUTION_ERROR = "Error occurred while executing command for {}: {}"
BF_SDE_ENV_VARS = ["SDE", "SDE_INSTALL"]
os.environ["GRPC_VERBOSITY"] = "NONE"
# _LOGGER = logging.getLogger(__name__)
# _LOGGER.setLevel(logging.INFO)


def main():
    # TODO: Change local/remote logic

    hostname = "192.168.178.68"
    username = "vagrant"
    program_name = "traffic_gen"
    grpc_port = 50052
    keyfile = "/Users/pascal/.ssh/tofinovm_key"
    ssh_port = 2222
    device_id = 0
    client_id = 0
    local = False
    p4_source = ["src/traffic_gen.p4", "src/util.p4", "src/headers.p4"]
    switch_processes = ["tofino-model", "bf_switchd"]
    project_dir = f"/tmp/{program_name}/"

    traffic_configuration = TrafficConfigurator()
    traffic_configuration.add_generation_port(68)
    traffic_configuration.add_output_port(
        5, 160, "100G"
    )  # Physical Port, Port ID(D_P), Port bw
    traffic_configuration.add_ip(ip_dst="10.2.2.2", ip_src="10.2.2.1")
    traffic_configuration.add_throughput(3000, "port_shaping")
    traffic_configuration.generate()
    attrs = traffic_configuration.get_attributes()
    for attr in attrs:
        print(attr)

    generator_runtime_s = 10
    output_port = 1
    device_port = 1
    generation_port = 68
    max_data_rate_mbps = 300
    # max_data_rate_mbps = 3000000
    pipe_id = 0
    pgen_pipe_id = 0
    g_timer_app_id = 1
    packet_length = 1024
    packet_batch_size = 1  # packets per batch
    packet_batch_number = 1  # batch number
    packet_buffer_offset = (
        144  # generated packets' payload will be taken from the offset in buffer
    )

    output_port_data = {"port": PortId(output_port)}
    port_shaping_key = {"dev_port": Exact(DevPort(device_port))}
    port_shaping_data = {
        "max_rate_enable": True,
        "unit": "BPS",
        "provisioning": "MIN_ERROR",
        "max_rate": max_data_rate_mbps * 1000,
        "max_burst_size": 1000,
    }

    timer_config_keys = {
        "ig_intr_md.ingress_port": generation_port,
        "hdr.timer.pipe_id": 0,
        "hdr.timer.app_id": 1,
        "hdr.timer.batch_id": 0,
        "hdr.timer.packet_id": 0,
    }

    packet_gen_action_config = {"timer_nanosec": 1}
    packet_gen_data_config = {
        "app_enable": False,
        "pkt_len": packet_length - 6,
        "pkt_buffer_offset": packet_buffer_offset,
        "pipe_local_source_port": generation_port,
        "increment_source_port": False,
        "batch_count_cfg": packet_batch_number - 1,
        "packets_per_batch_cfg": packet_batch_size - 1,
        "ibg": 0,
        "ibg_jitter": 0,
        "ipg": 0,
        "ipg_jitter": 0,
        "batch_counter": 0,
        "pkt_counter": 0,
        "trigger_counter": 0,
    }

    source_mask = "255.255.0.0"
    destination_mask = "255.255.255.255"

    packet = simple_ip_packet(
        pktlen=packet_length,
        eth_dst="00:01:02:03:04:05",
        eth_src="00:06:07:08:09:0a",
        ip_src="10.2.2.1",
        ip_dst="10.2.2.2",
    )

    ssh_client = ssh_conn(
        hostname=hostname, username=username, keyfile=keyfile, port=ssh_port
    )

    switch = TofinoSwitch(ssh_client)

    env_vars = switch.get_env_vars(BF_SDE_ENV_VARS, local)
    source_changed = switch.compare_and_handle_files(
        p4_source, project_dir, program_name, env_vars
    )
    switch.setup_virtual_interfaces(env_vars, project_dir)
    switch.handle_processes(switch_processes, program_name, env_vars, source_changed)
    bfrt_data = switch.get_bfrt_definition(
        program_name=program_name, remote_env_vars=env_vars, local=local
    )

    grpc_manager = GRPCManager(hostname, grpc_port, ssh_client, device_id, client_id)
    print("[OK] gRPC Connection established")
    bfrt_info, bfrt_helper = grpc_manager.get_bfrt_info_and_helper(bfrt_data)
    print(
        "[+] Copied and loaded extended Barefoot Runtime definition for Tofino target"
    )

    print("[+] Beginning traffic generator setup")
    traffic_generator = TrafficGenerator(bfrt_info, bfrt_helper, grpc_manager.client)

    print("  > Initialize timer table")
    traffic_generator.configure_port_shaping(
        program_name,
        port_shaping_data,
        port_shaping_key,
    )

    print("  > Configure timer table")
    traffic_generator.configure_timer_table(
        timer_config_keys,
        output_port_data,
        program_name,
    )

    print("  > Configure source and destination mask")
    traffic_generator.configure_egress_table(
        source_mask,
        destination_mask,
        output_port,
        program_name,
    )

    print("  > Configure traffic generator")
    traffic_generator.enable_packet_gen_port(program_name, generation_port)
    traffic_generator.configure_packet_gen(
        program_name,
        g_timer_app_id,
        packet_gen_action_config["timer_nanosec"],
        packet_gen_data_config,
    )

    print("  > Write initial packet into traffic generator buffer")
    traffic_generator.configure_packet_buffer(
        program_name,
        packet,
        packet_length,
        packet_buffer_offset,
    )

    print(f"[+] Running traffic generator for {generator_runtime_s} seconds...")
    traffic_generator.run_packet_generator(
        program_name, g_timer_app_id, generator_runtime_s
    )
    print("[OK] Run finished!")
    grpc_manager.close()

    return


if __name__ == "__main__":
    main()
