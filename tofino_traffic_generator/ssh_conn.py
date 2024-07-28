import os
import warnings
from cryptography.utils import CryptographyDeprecationWarning
import hashlib
import time

# Supress warning because of this issue https://github.com/paramiko/paramiko/issues/2419
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
import paramiko


class SSHCommandExecutionError(Exception):
    """Exception raised for errors in the SSH command execution."""

    def __init__(self, message="[ERROR] Error executing SSH command"):
        self.message = message
        super().__init__(self.message)


def ssh_conn(hostname, username=None, password=None, keyfile=None, port=22):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=hostname,
            username=username,
            password=password,
            key_filename=keyfile,
            port=port,
        )
        return client
    except Exception as e:
        print(f"[!] Failed to connect to {hostname}: {e}")
        return None


def ssh_exec(client, command, env_vars=None):
    try:
        return client.exec_command(command, environment=env_vars)
    except Exception as e:
        print(f"[!] Failed to execute command {command}: {e}")


def scp_put(client, localpath, remotepath):
    try:
        sftp = client.open_sftp()
        sftp.put(localpath, remotepath)
        sftp.close()
    except Exception as e:
        print(f"[!] Failed to copy file {localpath} to {remotepath}: {e}")


def scp_var_to_file(client, file_path, data):
    try:
        sftp = client.open_sftp()
        with sftp.open(file_path, "w") as remote_file:
            remote_file.write(data)
        sftp.close()
    except Exception as e:
        print(f"[!] Failed to create file {file_path}: {e}")
    return None


def ssh_delete_file(client, file):
    try:
        sftp = client.open_sftp()
        sftp.remove(file)
        sftp.close()
    except Exception as e:
        print(f"[!] Failed to delete file {file}: {e}")


def remote_file_read(client, remote_path):
    try:
        sftp = client.open_sftp()
        with sftp.open(remote_path, "r") as remote_file:
            file_content = remote_file.read()
        sftp.close()
        return file_content
    except Exception as e:
        print(f"[!] Failed to read file {remote_path}: {e}")
        return None


def create_remote_dir(client, remote_path):
    try:
        sftp = client.open_sftp()
        sftp.mkdir(remote_path)
        sftp.close()
    except Exception as e:
        print(f"[!] Failed to create directory {remote_path}: {e}")


def delete_remote_dir(client, remote_path):
    try:
        return ssh_exec(client, f"sudo rm -rf {remote_path}")
    except Exception as e:
        print(f"[!] Failed to delete directory {remote_path}: {e}")


def compute_local_file_checksum(file_path):
    """Compute the MD5 checksum of a local file."""
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def compute_remote_file_checksum(ssh_client, remote_file_path):
    """Compute the MD5 checksum of a remote file."""
    stdin, stdout, stderr = ssh_client.exec_command(f"md5sum {remote_file_path}")
    result = stdout.read().decode().strip()
    if result:
        return result.split()[0]
    return stdin, stdout, stderr


def compare_files(ssh_client, local_files, remote_dir):
    """Compare local files with remote files and check if they are the same or different."""
    comparison_results = {}
    all_files_same = True

    for local_file in local_files:
        file_name = os.path.basename(local_file)
        remote_file_path = os.path.join(remote_dir, file_name)

        local_checksum = compute_local_file_checksum(local_file)
        remote_checksum = compute_remote_file_checksum(ssh_client, remote_file_path)

        if remote_checksum is None:
            comparison_results[file_name] = "[!] Remote file does not exist"
            all_files_same = False
        elif local_checksum == remote_checksum:
            comparison_results[file_name] = "Same"
        else:
            comparison_results[file_name] = "Different"
            all_files_same = False

    return comparison_results, all_files_same


def check_remote_processes(ssh_client, process_names):
    """Check if a list of processes is running on the remote machine."""
    process_status = {}

    for process_name in process_names:
        stdin, stdout, stderr = ssh_client.exec_command(
            f"ps aux | grep -v grep | grep {process_name}"
        )
        output = stdout.read().decode().strip()
        if output:
            process_status[process_name] = True
        else:
            process_status[process_name] = False

    return process_status


def kill_running_processes(ssh_client, process_status):
    """Kill running processes on the remote machine using sudo killall."""
    killed_processes = []
    for process_name, is_running in process_status.items():
        if is_running:
            stdin, stdout, stderr = ssh_client.exec_command(
                f"sudo killall {process_name}"
            )
            stdout.channel.recv_exit_status()  # Wait for command to complete
            killed_processes.append(process_name)
    return killed_processes


def check_port_open(ssh_client, port):
    """Check if the specified port is open on the remote host."""
    try:
        stdin, stdout, stderr = ssh_exec(ssh_client, f"netstat -tuln | grep :{port}")
        output = stdout.read().decode().strip()
        if output:
            return True
        return False
    except Exception as e:
        print(f"[ERROR] Error checking port: {e}")
        return False


def wait_for_port(ssh_client, hostname, port, check_interval=5, timeout=30):
    """Wait until the specified port becomes available on the remote host."""
    start_time = time.time()
    while True:
        if check_port_open(ssh_client, port):
            print(f"[OK] Port {port} on {hostname} is now available!")
            break

        if time.time() - start_time > timeout:
            print(
                f"[!] Timeout reached: Port {port} on {hostname} is still not available."
            )
            break

        print(
            f"[*] Port {port} on {hostname} is not available yet. Retrying in {check_interval} seconds..."
        )
        time.sleep(check_interval)


def ssh_exec_commands(client, commands):
    for command in commands:
        ssh_exec(client, command)
