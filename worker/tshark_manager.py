import subprocess
import os

def save_tshark_config(file_config, tshark_path):
    with open(file_config, "w") as file:
        return file.write(tshark_path)

def get_tshark_config(file_config):
    try:
        if os.path.exists(file_config):
            tshark_path = ""
            with open(file_config,"r") as config_file:
                tshark_path = config_file.readline()
            return tshark_path
        else:
            return None
    except:
        return None

def check_tshark_installed():
    try:
        result = subprocess.run(["tshark", "--version"], capture_output=True, text=True)
        if "TShark" in result.stdout:
            return result.stdout.split('\n')[0]
        else:
            return None
    except Exception as ex:
        print(ex)
        return None