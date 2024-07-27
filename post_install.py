import os
import shutil
import sysconfig


def replace_files():
    # Define the paths to the source and target files
    source_dir = './deps'

    # Dynamically get the path to the site-packages directory in the virtual environment
    venv_path = os.path.join(os.getcwd(), '.venv')
    site_packages_dir = sysconfig.get_path('purelib', vars={'base': venv_path})

    target_dir = os.path.join(site_packages_dir, 'bfrt_helper/pb2')

    files_to_replace = ['bfruntime_pb2.py', 'bfruntime_pb2_grpc.py']

    for file_name in files_to_replace:
        source_file = os.path.join(source_dir, file_name)
        target_file = os.path.join(target_dir, file_name)

        if os.path.exists(source_file):
            print(f"Replacing {target_file} with {source_file}")
            shutil.copy2(source_file, target_file)
        else:
            print(f"Source file {source_file} does not exist")


if __name__ == "__main__":
    replace_files()
