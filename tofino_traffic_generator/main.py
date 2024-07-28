import os
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

    virtual_switch = True
    local = False

    p4_source = ["src/traffic_gen.p4", "src/util.p4", "src/headers.p4"]
    switch_processes = ["tofino-model", "bf_switchd"]
    project_dir = f"/tmp/{program_name}/"

    traffic_configuration = TrafficConfigurator(virtual_switch=virtual_switch)
    traffic_configuration.configure_generator(port=68, generation_time_s=5)
    traffic_configuration.add_virtual_output_port(1)
    traffic_configuration.add_physical_output_port(10, "100G")
    traffic_configuration.add_packet_data(
        source_cidr="10.2.2.0/24", destination_cidr="10.2.2.1/32"
    )
    traffic_configuration.craft_tcp_packet()
    traffic_configuration.add_throughput(3000, "port_shaping")
    traffic_configuration.generate()

    ssh_client = ssh_conn(
        hostname=hostname, username=username, keyfile=keyfile, port=ssh_port
    )

    switch = TofinoSwitch(ssh_client)

    env_vars = switch.get_env_vars(BF_SDE_ENV_VARS, local)
    source_changed = switch.compare_and_handle_files(
        p4_source, project_dir, program_name, env_vars
    )

    output_device_port = 1
    if virtual_switch:
        switch.setup_interfaces(env_vars, project_dir)
        output_device_port = traffic_configuration.output_virtual_port
        switch.handle_processes(
            switch_processes, program_name, env_vars, source_changed
        )
    else:
        switch.handle_processes(
            switch_processes, program_name, env_vars, source_changed
        )
        switch.setup_interfaces(env_vars, project_dir)
        # This need to be fixed
        for port in switch.phy_port_table:
            if port.get("PORT") == f"{traffic_configuration.output_physical_port}/0":
                output_device_port = port["D_P"]

    bfrt_data = switch.get_bfrt_definition(
        program_name=program_name, remote_env_vars=env_vars, local=local
    )

    output_port_data = {"port": PortId(output_device_port)}
    port_shaping_key = {"dev_port": Exact(DevPort(output_device_port))}
    port_shaping_data = {
        "max_rate_enable": True,
        "unit": "BPS",
        "provisioning": "MIN_ERROR",
        "max_rate": traffic_configuration.throughput * 1000,
        "max_burst_size": 1000,
    }

    timer_config_keys = {
        "ig_intr_md.ingress_port": traffic_configuration.generation_port,
        "hdr.timer.pipe_id": 0,
        "hdr.timer.app_id": 1,
        "hdr.timer.batch_id": 0,
        "hdr.timer.packet_id": 0,
    }

    packet_gen_action_config = {"timer_nanosec": 1}

    packet_gen_data_config = {
        "app_enable": False,
        "pkt_len": traffic_configuration.pkt_len - 6,
        "pkt_buffer_offset": traffic_configuration.packet_buffer_offset,
        "pipe_local_source_port": traffic_configuration.generation_port,
        "increment_source_port": False,
        "batch_count_cfg": traffic_configuration.packet_batch_number - 1,
        "packets_per_batch_cfg": traffic_configuration.packet_batch_size - 1,
        "ibg": 0,
        "ibg_jitter": 0,
        "ipg": 0,
        "ipg_jitter": 0,
        "batch_counter": 0,
        "pkt_counter": 0,
        "trigger_counter": 0,
    }

    grpc_manager = GRPCManager(hostname, grpc_port, ssh_client)
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
        traffic_configuration.source_mask,
        traffic_configuration.destination_mask,
        output_device_port,
        program_name,
    )

    print("  > Configure traffic generator")
    traffic_generator.enable_packet_gen_port(
        program_name, traffic_configuration.generation_port
    )
    traffic_generator.configure_packet_gen(
        program_name,
        traffic_configuration.g_timer_app_id,
        packet_gen_action_config["timer_nanosec"],
        packet_gen_data_config,
    )

    print("  > Write initial packet into traffic generator buffer")
    traffic_generator.configure_packet_buffer(
        program_name,
        traffic_configuration.packet,
        traffic_configuration.pkt_len,
        traffic_configuration.packet_buffer_offset,
    )

    print(
        f"[+] Running traffic generator for {traffic_configuration.generation_time_s} seconds..."
    )
    traffic_generator.run_packet_generator(
        program_name,
        traffic_configuration.g_timer_app_id,
        traffic_configuration.generation_time_s,
    )
    print("[OK] Run finished!")
    grpc_manager.close()

    return


if __name__ == "__main__":
    main()
