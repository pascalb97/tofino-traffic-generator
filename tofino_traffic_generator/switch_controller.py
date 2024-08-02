import json
import os
import socket
import struct
import time
import signal
import sys
import threading
from queue import Queue
from threading import Thread
import bfrt_helper.pb2.bfruntime_pb2 as bfruntime_pb2
import bfrt_helper.pb2.bfruntime_pb2_grpc as bfruntime_pb2_grpc
import grpc
from contextlib import contextmanager
from bfrt_helper.bfrt import BfRtHelper, BfRtInfo
from bfrt_helper.fields import DevPort, Field, PortId
from bfrt_helper.match import Exact
from jinja2 import Environment, FileSystemLoader

from ssh_conn import (
    SSHCommandExecutionError,
    check_remote_processes,
    compare_files,
    create_remote_dir,
    delete_remote_dir,
    kill_running_processes,
    remote_file_read,
    scp_put,
    scp_var_to_file,
    ssh_exec,
    wait_for_port,
)

ENV_VAR_NOT_FOUND_ERROR = "Environment variable '{}' not found or empty."
COMMAND_EXECUTION_ERROR = "Error occurred while executing command for {}: {}"
BF_SDE_ENV_VARS = ["SDE", "SDE_INSTALL"]


@contextmanager
def suppress_stdout():
    with open(os.devnull, "w") as devnull:
        old_stdout = sys.stdout
        sys.stdout = devnull
        try:
            yield
        finally:
            sys.stdout = old_stdout


def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def mac2int(mac_str):
    return int(mac_str.replace(":", ""), 16)


def get_number_of_bits(byte_array):
    return len(byte_array) * 8


class IntField(Field):
    bitwidth = 32

    def __init__(self, value=0, bitwidth=None):
        super().__init__(value)  # Initialize the value attribute from the parent class
        if bitwidth is not None:
            self.bitwidth = bitwidth


class PacketField(Field):
    # 16 KByte packet buffer
    bitwidth = 16384


class GRPCManager:
    def __init__(
        self,
        hostname="localhost",
        grpc_port=50052,
        ssh_client=None,
        device_id=0,
        client_id=0,
    ):
        self.hostname = hostname
        self.grpc_port = grpc_port
        self.ssh_client = ssh_client
        self.device_id = device_id
        self.client_id = client_id
        self.client = self.establish_connection_based_on_type()
        self.stream_out_queue = Queue()
        self.stream_in_queue = Queue()
        self.stream = self.client.StreamChannel(self.stream_req_iterator())
        self.stream_recv_thread = Thread(target=self.stream_recv, args=(self.stream,))
        self.stream_recv_thread.start()
        signal.signal(signal.SIGINT, self.close)

    def get_bfrt_info_and_helper(self, bfrt_data):
        bfrt_info = BfRtInfo(bfrt_data)
        bfrt_helper = BfRtHelper(self.device_id, self.client_id, bfrt_info)
        # Get full table definition (non p4 tables)
        with suppress_stdout():
            request = bfrt_helper.create_subscribe_request()
            self.stream_out_queue.put(request)
            self.stream_in_queue.get()
            request = bfrt_helper.create_get_pipeline_request()
            response = self.client.GetForwardingPipelineConfig(request)

            program_name = response.config[0].p4_name
            data = response.non_p4_config.bfruntime_info.decode("utf-8")
            non_p4_config = json.loads(data)

        p4_config = None

        for config in response.config:
            if program_name == config.p4_name:
                p4_config = json.loads(config.bfruntime_info)
                p4_config.get("tables").extend(non_p4_config.get("tables"))

        # Load full table definition
        bfrt_info = BfRtInfo(p4_config)
        bfrt_helper = BfRtHelper(self.device_id, self.client_id, bfrt_info)

        return bfrt_info, bfrt_helper

    def establish_grpc_connection(self, channel):
        """
        This method establishes a gRPC connection given an opened channel.
        """
        client = bfruntime_pb2_grpc.BfRuntimeStub(channel)
        return client

    def establish_local_grpc_connection(self):
        channel = grpc.insecure_channel(f"{self.hostname}:{self.grpc_port}")
        return self.establish_grpc_connection(channel)

    def establish_remote_grpc_connection(self):
        wait_for_port(self.ssh_client, self.hostname, self.grpc_port)
        channel = grpc.insecure_channel(f"{self.hostname}:{self.grpc_port}")
        return self.establish_grpc_connection(channel)

    def establish_connection_based_on_type(self):
        if self.ssh_client is None:
            return self.establish_local_grpc_connection()
        else:
            return self.establish_remote_grpc_connection()

    def stream_req_iterator(self):
        while True:
            p = self.stream_out_queue.get()
            if p is None:
                break
            print("[*] Stream sending: ", p)
            yield p

    def stream_recv(self, stream):
        try:
            for p in stream:
                print("[+] Stream received: ", p)
                self.stream_in_queue.put(p)
        except Exception as e:
            print(str(e))

    def close(self):
        self.stream_out_queue.put(None)
        self.stream_recv_thread.join()


class TofinoSwitch:
    COMMAND_EXECUTION_ERROR = "[ERROR] Error executing command: {}"
    ENV_VAR_NOT_FOUND_ERROR = "[ERROR] Environment variable {} not found"

    def __init__(self, ssh_client, virtual_switch=True):
        self.ssh_client = ssh_client
        self.virtual_switch = virtual_switch

    def fetch_env_var(self, var_name):
        stdin, stdout, stderr = ssh_exec(
            self.ssh_client, f". .profile > /dev/null ; echo ${var_name}"
        )
        error_message = stderr.read().decode("ascii").strip()
        if (
            error_message
            and "insmod: ERROR: could not insert module" not in error_message
        ):
            raise Exception(
                self.COMMAND_EXECUTION_ERROR.format(var_name, error_message)
            )

        result = stdout.read().decode("ascii").strip("\n")
        if not result:
            raise ValueError(self.ENV_VAR_NOT_FOUND_ERROR.format(var_name))

        return result

    def get_env_vars(self, var_names, local):
        if not local:
            env_vars = {
                var_name: self.fetch_env_var(var_name) for var_name in var_names
            }
        else:
            env_vars = {var_name: os.getenv(var_name) for var_name in var_names}
        return env_vars

    def get_bfrt_definition(self, program_name, remote_env_vars=None, local=True):
        file_path_template = "{install_path}/share/tofinopd/{program_name}/bf-rt.json"

        def load_local_data():
            install_path = os.getenv("SDE_INSTALL")
            file_path = file_path_template.format(
                install_path=install_path, program_name=program_name
            )
            with open(file_path) as json_file:
                return json.load(json_file)

        def load_remote_data():
            install_path = remote_env_vars["SDE_INSTALL"]
            file_path = file_path_template.format(
                install_path=install_path, program_name=program_name
            )
            bfrt_json = remote_file_read(self.ssh_client, file_path)
            return json.loads(bfrt_json)

        return load_local_data() if local else load_remote_data()

    def remote_file_read(self, file_path):
        # Dummy function for reading remote files. Implement as needed.
        pass

    def template_to_var(self, template_file: str, template_data: dict):
        env = Environment(loader=FileSystemLoader("."))
        template = env.get_template(template_file)
        return template.render(template_data)

    def remote_veth_setup(self, num_ports=64):
        try:
            script_content = self.template_to_var(
                "templates/veth-setup.sh.j2", {"num_ports": num_ports}
            )
            command = f"sudo /bin/bash -s <<'EOF'\n{script_content}\nEOF"
            stdin, stdout, stderr = ssh_exec(self.ssh_client, command)
            if stderr.read():
                raise SSHCommandExecutionError(
                    f"Error during remote veth setup: {stderr.read()}"
                )
        except Exception as e:
            raise SSHCommandExecutionError(
                f"Unexpected error during remote veth setup: {str(e)}"
            )
        return stdin, stdout, stderr

    def tofino_model_port_setup(self, remote_env_vars, num_ports):
        try:
            self.remote_veth_setup(num_ports)
            command = (
                f'sudo /bin/bash {remote_env_vars["SDE_INSTALL"]}/bin/veth_setup.sh'
            )
            stdin, stdout, stderr = ssh_exec(self.ssh_client, command)
            if stderr.read():
                raise SSHCommandExecutionError(
                    f"Error during model port setup: {stderr.read()}"
                )
        except Exception as e:
            raise SSHCommandExecutionError(
                f"Unexpected error during model port setup: {str(e)}"
            )
        return stdin, stdout, stderr

    def generate_port_to_veth_json(self, num_ports):
        port_to_veth = []
        veth_counter = 0

        for port in range(num_ports):
            port_to_veth.append(
                {"device_port": port, "veth1": veth_counter, "veth2": veth_counter + 1}
            )
            veth_counter += 2

        result = {"PortToVeth": port_to_veth}
        return json.dumps(result, indent=4)

    def write_port_to_veth_json(self, remote_dir, num_ports):
        ports_json = self.generate_port_to_veth_json(64)
        scp_var_to_file(self.ssh_client, f"{remote_dir}/ports.json", ports_json)

    def install_p4_program(self, program_name, project_dir, remote_env_vars):
        scp_put(
            self.ssh_client,
            f"src/{program_name}.p4",
            f"{project_dir}/{program_name}.p4",
        )
        scp_put(self.ssh_client, "src/headers.p4", f"{project_dir}/headers.p4")
        scp_put(self.ssh_client, "src/util.p4", f"{project_dir}/util.p4")
        template_data = {
            "program_name": program_name,
            "project_dir": project_dir,
            "sde_path": remote_env_vars["SDE"],
            "sde_install_path": remote_env_vars["SDE_INSTALL"],
        }
        try:
            script_content = self.template_to_var(
                "templates/build.sh.j2", template_data
            )
            command = f"sudo /bin/bash -s <<'EOF'\n{script_content}\nEOF"
            stdin, stdout, stderr = ssh_exec(self.ssh_client, command)
            for line in stderr.readlines():
                print(line.strip())
            if stderr.read():
                raise SSHCommandExecutionError(
                    f"Error during P4 compilation and/or install: {stderr.read()}"
                )
        except Exception as e:
            raise SSHCommandExecutionError(
                f"Unexpected error during compilation and/or install: {str(e)}"
            )
        return stdin, stdout, stderr

    def start_tofino_model(self, program_name, remote_env_vars):
        return ssh_exec(
            self.ssh_client,
            f". .profile > /dev/null ; nohup /bin/bash {remote_env_vars['SDE']}/run_tofino_model.sh"
            f" -p {program_name} -f /tmp/{program_name}/ports.json > /dev/null 2>&1 &",
        )

    def start_bfswitch(self, program_name, remote_env_vars):
        return ssh_exec(
            self.ssh_client,
            f". .profile > /dev/null ; nohup /bin/bash {remote_env_vars['SDE']}/run_switchd.sh"
            f" -p {program_name} > /dev/null 2>&1 &",
        )

    def start_bfshell(self, remote_env_vars):
        return ssh_exec(
            self.ssh_client,
            f". .profile > /dev/null ; /bin/bash {remote_env_vars['SDE']}/run_bfshell.sh -f test_config.txt",
        )

    def stop_tofino_model(self):
        return ssh_exec(self.ssh_client, "sudo killall tofino-model")

    def stop_bfswitch(self):
        return ssh_exec(self.ssh_client, "sudo killall bf_switchd")

    def is_port_open(self, host, port, timeout=1):
        """Check if a port is open on a remote host."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            try:
                s.connect((host, port))
                return True
            except (socket.timeout, ConnectionRefusedError):
                return False

    def wait_for_grpc_port(self, host, port, timeout=1, interval=5):
        """Wait until the gRPC port becomes available."""
        print(f"Checking for gRPC port {port} on {host}...")
        while not self.is_port_open(host, port, timeout):
            print(
                f"Port {port} is not available yet. Retrying in {interval} seconds..."
            )
            time.sleep(interval)
        print(f"Port {port} is now available!")

    def compare_and_handle_files(
        self, local_files, remote_dir, program_name, remote_env_vars
    ):
        comparison_results, all_files_same = compare_files(
            self.ssh_client, local_files, remote_dir
        )
        print("[*] Comparing generated source files with existing source files...")
        for file, status in comparison_results.items():
            print(f"  > {file}: {status}")
        if not all_files_same:
            print("[-] Removing remote project dir")
            delete_remote_dir(self.ssh_client, remote_dir)
            print("[+] Creating remote project dir")
            create_remote_dir(self.ssh_client, remote_path=remote_dir)
            print("[*] Compiling and installing traffic generator P4 application")
            self.install_p4_program(program_name, remote_dir, remote_env_vars)
            print("[OK] Compilation and installation successful!")
            return True
        else:
            print("[!] P4 source has not changed, skipped compilation step.")
            return False

    def get_phy_port_list(self, bfshell_show_output):
        start_marker = "bf-sde.pm> show"
        end_marker = "bf-sde.pm> exit"
        display = False
        lines = []
        for line in bfshell_show_output:
            if start_marker in line:
                display = True
                continue
            if end_marker in line:
                display = False
                break
            if display:
                lines.append(line.strip())
        return lines

    def parse_phy_port_list(self, raw_port_table):
        headers = [header.strip() for header in raw_port_table[1].split("|")]
        data = []
        for line in raw_port_table[2:]:  # Skip the header and separator lines
            if line.strip() == "" or line.startswith("-----"):
                continue  # Skip empty lines or separator lines
            values = [value.strip() for value in line.split("|")]
            entry = dict(zip(headers, values))
            data.append(entry)
        ssh_exec(self.ssh_client, "sudo rm -f /tmp/port_config.txt")
        return data

    def setup_interfaces(self, remote_env_vars, project_dir):
        if self.virtual_switch:
            print("[+] Setting up virtual ports")
            self.tofino_model_port_setup(remote_env_vars, 64)
            self.write_port_to_veth_json(project_dir, 64)
        else:
            print("[+] Setting up physical ports")
            scp_put(self.ssh_client, "src/port_config.txt", "/tmp/port_config.txt")
            stdin, stdout, stderr = ssh_exec(
                self.ssh_client,
                f". .profile > /dev/null ; /bin/bash {remote_env_vars['SDE']}/run_bfshell.sh -f /tmp/port_config.txt"
            )
            raw_port_table = self.get_phy_port_list(stdout.readlines())
            self.phy_port_table = self.parse_phy_port_list(raw_port_table)

    def handle_processes(
        self, process_names, program_name, remote_env_vars, source_changed
    ):
        process_status = check_remote_processes(self.ssh_client, process_names)
        any_not_running = any(not status for status in process_status.values())
        if any_not_running or source_changed:
            print("[!] Killing existing switch processes")
            killed_processes = kill_running_processes(self.ssh_client, process_status)
            for process in killed_processes:
                print(f"[-] Killed {process}")
            time.sleep(3)
            if self.virtual_switch:
                print("[*] Starting tofino model...")
                self.start_tofino_model(program_name, remote_env_vars)
                time.sleep(3)
            print("[*] Starting bf_switch...")
            self.start_bfswitch(program_name, remote_env_vars)


class TrafficGenerator:
    def __init__(self, bfrt_info, bfrt_helper, grpc_client):
        self.bfrt_info = bfrt_info
        self.bfrt_helper = bfrt_helper
        self.grpc_client = grpc_client
        self.phy_port_table = []

    def fix_bfrt_input(self, val, type_info, bitwidth=None):
        if "uint" in type_info or "byte" in type_info:
            if isinstance(val, int):
                val = IntField(val)
                val.bitwidth = bitwidth if bitwidth else 8
        return val

    def fix_bfrt_input_data(self, table_name, data):
        transformed_data = {}
        for data, val in data.items():
            field = self.bfrt_info.get_data_field(table_name, data)
            if field is not None:
                type_info = field.singleton.type["type"]
                bitwidth = (
                    int(type_info.replace("uint", "")) if "uint" in type_info else None
                )
                transformed_data[data] = self.fix_bfrt_input(val, type_info, bitwidth)
            else:
                transformed_data[data] = val
        return transformed_data

    def fix_bfrt_input_keys(self, table_name, keys):
        transformed_data = {}
        for key, val in keys.items():
            field = self.bfrt_info.get_key(table_name, key)
            if field is not None:
                type_info = field.type["type"]
                transformed_data[key] = self.fix_bfrt_input(
                    val, type_info, field.type["width"]
                )
            else:
                transformed_data[key] = val
        return transformed_data

    def delete_table(self, program_name, table_name):
        bfrt_request = self.bfrt_helper.create_write_request(program_name)
        bfrt_table_entry = self.bfrt_helper.create_table_entry(table_name)
        bfrt_update = bfrt_request.updates.add()
        bfrt_update.type = bfruntime_pb2.Update.Type.DELETE
        bfrt_update.entity.table_entry.CopyFrom(bfrt_table_entry)
        return bfrt_request

    def mod_create_table_data_write(
        self,
        program_name,
        table_name,
        key,
        data,
        update_type=bfruntime_pb2.Update.Type.INSERT,
    ):
        bfrt_request = self.bfrt_helper.create_write_request(program_name)
        bfrt_table_entry = self.bfrt_helper.create_table_entry(table_name)
        bfrt_key_fields = self.bfrt_helper.create_key_fields(table_name, key)
        bfrt_table_entry.key.fields.extend(bfrt_key_fields)
        bfrt_table_data = bfruntime_pb2.TableData()

        for field_name, value in data.items():
            field = self.bfrt_info.get_data_field(table_name, field_name)
            bfrt_data_field = self.bfrt_helper.create_data_field(field.singleton, value)
            bfrt_table_data.fields.extend([bfrt_data_field])

        bfrt_table_entry.data.CopyFrom(bfrt_table_data)
        bfrt_update = bfrt_request.updates.add()
        bfrt_update.type = update_type
        bfrt_update.entity.table_entry.CopyFrom(bfrt_table_entry)
        return bfrt_request

    def configure_port_shaping(self, program_name, port_shaping_data, port_shaping_key):
        status = {}
        table_pairs = {
            "tf1.tm.port.sched_cfg": {
                "max_rate_enable": port_shaping_data["max_rate_enable"]
            },
            "tf1.tm.port.sched_shaping": {
                "unit": port_shaping_data["unit"],
                "provisioning": port_shaping_data["provisioning"],
                "max_rate": port_shaping_data["max_rate"],
                "max_burst_size": port_shaping_data["max_burst_size"],
            },
        }
        for table_name, data in table_pairs.items():
            data = self.fix_bfrt_input_data(table_name, data)
            request, response = self.process_table_data(
                program_name, table_name, port_shaping_key, data
            )
            status[table_name] = [request, response]
        return status

    def process_table_data(self, program_name, table_name, key, data):
        table = self.bfrt_info.get_table(table_name)
        request = self.mod_create_table_data_write(
            program_name=program_name,
            table_name=table.name,
            key=key,
            data=data,
            update_type=bfruntime_pb2.Update.Type.MODIFY,
        )
        response = self.grpc_client.Write(request)
        return request, response

    def clean_table(self, program_name, table_name):
        table_info = self.bfrt_info.get_table(table_name)
        request = self.delete_table(
            program_name=program_name,
            table_name=table_info.name,
        )
        response = self.grpc_client.Write(request)
        return request, response

    def configure_timer_table(self, timer_config_keys, timer_config_data, program_name):
        timer_fwd_table = self.bfrt_info.get_table("pipe.SwitchIngress.t")
        self.clean_table(program_name, timer_fwd_table.name)
        keys = self.fix_bfrt_input_keys(timer_fwd_table.name, timer_config_keys)
        keys = {key: Exact(value) for key, value in keys.items()}
        request = self.bfrt_helper.create_table_write(
            program_name=program_name,
            table_name=timer_fwd_table.name,
            key=keys,
            action_name="SwitchIngress.match",
            action_params=timer_config_data,
            update_type=bfruntime_pb2.Update.Type.INSERT,
        )
        response = self.grpc_client.Write(request)
        return request, response

    def configure_egress_table(
        self, source_mask, destination_mask, output_port, program_name
    ):
        status = {}
        egress_table = self.bfrt_info.get_table("pipe.SwitchEgress.egress_table")
        status["clean_table"] = self.clean_table(program_name, egress_table.name)
        request = self.bfrt_helper.create_table_write(
            program_name,
            egress_table.name,
            {"eg_intr_md.egress_port": Exact(PortId(output_port))},
            action_name="SwitchEgress.replace_ip_address",
            action_params={
                "s_mask": IntField(ip2int(source_mask)),
                "d_mask": IntField(ip2int(destination_mask)),
            },
            update_type=bfruntime_pb2.Update.Type.INSERT,
        )
        response = self.grpc_client.Write(request)
        status["create_table"] = [request, response]
        return status

    def enable_packet_gen_port(self, program_name, generation_port):
        pktgen_port_cfg_table = self.bfrt_info.get_table("tf1.pktgen.port_cfg")
        request = self.mod_create_table_data_write(
            program_name=program_name,
            table_name=pktgen_port_cfg_table.name,
            key={"dev_port": Exact(DevPort(generation_port))},
            data={"pktgen_enable": True},
            update_type=bfruntime_pb2.Update.Type.INSERT,
        )
        response = self.grpc_client.Write(request)
        return request, response

    def configure_packet_gen(self, program_name, app_id, timer_ns, data):
        table = self.bfrt_info.get_table("tf1.pktgen.app_cfg")
        table_name = table.name
        data = self.fix_bfrt_input_data(table_name, data)
        request = self.bfrt_helper.create_write_request(program_name)
        table_entry = self.bfrt_helper.create_table_entry(table_name)
        key = {"app_id": Exact(IntField(app_id))}
        key_fields = self.bfrt_helper.create_key_fields(table_name, key)
        table_entry.key.fields.extend(key_fields)
        action_spec = self.bfrt_info.get_action_spec(
            table_name, "trigger_timer_periodic"
        )
        table_data = bfruntime_pb2.TableData()
        table_data.action_id = action_spec.id
        action_field = self.bfrt_info.get_action_field(
            table_name, "trigger_timer_periodic", "timer_nanosec"
        )
        timer_action = self.bfrt_helper.create_data_field(
            action_field, IntField(timer_ns)
        )
        table_data.fields.extend([timer_action])
        for field_name, value in data.items():
            field = self.bfrt_info.get_data_field(table_name, field_name)
            data_field = self.bfrt_helper.create_data_field(field.singleton, value)
            table_data.fields.extend([data_field])
        table_entry.data.CopyFrom(table_data)
        update = request.updates.add()
        update.type = bfruntime_pb2.Update.Type.MODIFY
        update.entity.table_entry.CopyFrom(table_entry)
        response = self.grpc_client.Write(request)
        return request, response

    def configure_packet_buffer(
        self, program_name, packet, packet_length, buffer_offset
    ):
        pktgen_pkt_buffer_table = self.bfrt_info.get_table("tf1.pktgen.pkt_buffer")
        buffer_field_id = self.bfrt_info.get_data_field_id(
            pktgen_pkt_buffer_table.name, "buffer"
        )
        data_field = bfruntime_pb2.DataField()
        data_field.field_id = buffer_field_id
        data_field.stream = bytes(packet)[6:]
        request = self.bfrt_helper.create_write_request(program_name)
        bfrt_table_entry = self.bfrt_helper.create_table_entry(
            pktgen_pkt_buffer_table.name
        )
        key = {
            "pkt_buffer_offset": Exact(IntField(buffer_offset)),
            "pkt_buffer_size": Exact(IntField(packet_length - 6)),
        }
        bfrt_key_fields = self.bfrt_helper.create_key_fields(
            pktgen_pkt_buffer_table.name, key
        )
        bfrt_table_entry.key.fields.extend(bfrt_key_fields)
        bfrt_table_data = bfruntime_pb2.TableData()
        bfrt_table_data.fields.extend([data_field])
        bfrt_table_entry.data.CopyFrom(bfrt_table_data)
        bfrt_update = request.updates.add()
        bfrt_update.type = bfruntime_pb2.Update.Type.MODIFY
        bfrt_update.entity.table_entry.CopyFrom(bfrt_table_entry)
        response = self.grpc_client.Write(request)
        return request, response

    def packet_generation(self, program_name, app_id, action, enable):
        pktgen_app_cfg_table = self.bfrt_info.get_table("tf1.pktgen.app_cfg")
        request = self.bfrt_helper.create_write_request(program_name)
        table_entry = self.bfrt_helper.create_table_entry(pktgen_app_cfg_table.name)
        key = {"app_id": Exact(IntField(app_id))}
        key_fields = self.bfrt_helper.create_key_fields(pktgen_app_cfg_table.name, key)
        table_entry.key.fields.extend(key_fields)
        info_action = self.bfrt_info.get_action_spec(pktgen_app_cfg_table.name, action)
        table_data = bfruntime_pb2.TableData()
        table_data.action_id = info_action.id
        app_enable_field = self.bfrt_info.get_data_field(
            pktgen_app_cfg_table.name, "app_enable"
        )
        packetgen_action = self.bfrt_helper.create_data_field(
            app_enable_field.singleton, enable
        )
        table_data.fields.extend([packetgen_action])
        table_entry.data.CopyFrom(table_data)
        update = request.updates.add()
        update.type = bfruntime_pb2.Update.Type.MODIFY
        update.entity.table_entry.CopyFrom(table_entry)
        response = self.grpc_client.Write(request)
        return request, response

    def start_packet_generation(self, program_name, app_id):
        return self.packet_generation(
            program_name,
            app_id,
            "trigger_timer_periodic",
            True,
        )

    def stop_packet_generation(self, program_name, app_id):
        return self.packet_generation(
            program_name,
            app_id,
            "trigger_timer_one_shot",
            False,
        )

    
    def run_packet_generator(self, program_name, app_id, virtual_switch, output_port=None, runtime_s=5, measure_res_s=1):
        status = {}
        port_metrics = {}
        port_metrics["time_s"] = []

        def packet_generation():
            status["start_packet_generation"] = self.start_packet_generation(
                program_name, app_id
            )
            time.sleep(runtime_s)
            status["stop_packet_generation"] = self.stop_packet_generation(
                program_name, app_id
            )

        
        if virtual_switch:
            if output_port is not None:
                print("[!] Port metrics are not available on the model - skipping metrics collection...")
            packet_generation()
            return status, port_metrics

    
        else:
            if output_port is None:
                print("[!] No output device port specified - skipping metrics collection...")
                return status, port_metrics

            port_stat_map = {}
            port_stat_table = self.bfrt_info.get_table("$PORT_STAT")
            for field in port_stat_table.data:
                port_stat_map[field.singleton.id] =  field.singleton.name

            print(f"  > Collecting port metrics from device port {output_port}...")
            request = self.bfrt_helper.create_table_read(program_name,"$PORT_STAT", {'$DEV_PORT': Exact(DevPort(output_port))})


            def capture_port_metrics():
                time.sleep(measure_res_s)
                response = self.grpc_client.Read(request)
                port_metrics["time_s"].append(time.perf_counter()-start_time)
                data = response.next()
                for field in data.entities[0].table_entry.data.fields:
                    field_id = field.field_id
                    field_value = int.from_bytes(field.stream, byteorder="big")
                    metric_key = port_stat_map[field_id]
                    
                    if metric_key not in port_metrics:
                        port_metrics[metric_key] = [field_value]
                    else:
                        port_metrics[metric_key].append(field_value)
            
            thread = threading.Thread(target=packet_generation)
            thread.start()

            start_time = time.perf_counter()
            while thread.is_alive():
                capture_port_metrics()
            # Append final values
            capture_port_metrics()
            thread.join()        
            
            return status, port_metrics

        
