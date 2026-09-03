
from output_manager.output_manager import *
from worker.process_file import *
from worker.tshark_manager import *
from worker.processing_manager import ProcessingManager
from output_manager.output_manager import *
from output_manager.banner import *
from datetime import datetime 
from rich.console import Console
import multiprocessing
import os.path
import sys
import argparse


def get_input_files(arg:str) -> list[str]:
    input_files: list[str] = []
    if os.path.isdir(arg):
        for filename in os.listdir(input_folder):
            file_path = os.path.join(input_folder, filename)
            if os.path.isfile(file_path):
                input_files.append(file_path)
    else:
        if os.path.isfile(args.input):
            input_files = [args.input]
    return input_files

def get_input_folder(arg:str) -> str:
    if os.path.isdir(arg):
        return arg
    else:
        return os.path.dirname(arg)

def get_task_name(arg:str) -> str:
    time_id = datetime.now().isoformat(timespec='seconds').replace(':', '').replace('-', '').replace('.', '_')[2:]
    return time_id

if __name__ == "__main__":
    console = Console()
    print_banner()
    #Flags
    parser = argparse.ArgumentParser(prog="CredsDetect", description="Program for extracting credentials from traffic files")
    parser.add_argument('input', type=str, help='path to the file or directory containing the traffic capture files')
    parser.add_argument("-t", "--threads", type=int, help="number of threads to process")
    parser.add_argument("-n", "--name", type=str, help="name of the task to record the prefix of the result files")
    parser.add_argument("-o", "--output", type=str, help="path to the directory for results")
    parser.add_argument("-p", "--tshark_path", type=str, help="path to the TShark")
    parser.add_argument("-c", "--current", action="store_true",  help="output current results")
    parser.add_argument("-q", "--quite", action="store_true",  help="dont show dashboard")
    args = parser.parse_args()
    show_machines = False #Вывод аутентификационных данных машинных учётных записей NTLM, Kerberos

    #Input files
    input_folder = get_input_folder(args.input)
    input_files = get_input_files(args.input)
    if len(input_files) == 0:
        console.print(f"[!] Files not found")
        sys.exit(1)
    #Count files
    count_files = len(input_files)
    console.print(f"{count_files} files were found in the directory {input_folder}")
    #Found TShark
    config_tshark = True
    config_path = "config.txt"
    if not args.tshark_path is None:
        save_tshark_config(config_path, args.tshark_path)
        console.print(f'Save path to TShark in config file ({args.tshark_path})')
    tshark_path = get_tshark_config(config_path)
    if (tshark_path is None) or not os.path.exists(tshark_path):
        config_tshark = False
        console.print('The correct path to the TShark is not specified in the configuration file')
    else:
        console.print(f"TShark path in config.txt {tshark_path}")
    if not config_tshark:
        tshark_version = check_tshark_installed()
        if not tshark_version is None:
            console.print(f"{tshark_version} detected in the environment")
            tshark_path = "tshark"
        else:
            console.print("Tshark was not detected in the environment")
            sys.exit(1)
    #Count processes
    count_processes = min(multiprocessing.cpu_count(), len(input_files))
    if not args.threads is None:
        count_processes = min(len(input_files), args.threads)
    #Filter protocols
    default_protocols = ['kerberos.as_req_element',
                         'kerberos.as_rep_element',
                         'kerberos.tgs_rep_element',
                         'ntlmssp',
                         'http.proxy_authenticate',
                         'http.proxy_authorization',
                         'http.authorization',
                         'pop',
                         'imap',
                         'smtp',
                         'ftp',
                         'ldap']
    filter_protocols = ' or '.join(default_protocols)
    console.print(f'Protocol filtering is performed with "{filter_protocols}"')
    #Taskname
    taskname = get_task_name(arg=args.input)
    if not args.name is None:
        taskname = args.name

    #Output folder
    default_results_folder = os.path.join(os.getcwd(), 'results')
    results_folder = args.output if args.output is not None else default_results_folder
    output_folder = os.path.join(results_folder, taskname)
    os.makedirs(output_folder, exist_ok=True)
    console.print(f"Output directory set to: {output_folder}")

    file_processor = ProcessingManager(
        count_processes=count_processes,
        input_files=input_files,
        filter_protocols=filter_protocols,
        tshark_path=tshark_path,
        current_result=args.current,
        quite=args.quite,
        output_folder=output_folder,
        taskname=taskname)
    
    file_processor.process_files(process_file_func=process_file)
    global_result_data = file_processor.results

    console.print('[dim][*] Saving results...[/dim]')
    print_results(output_folder, taskname, global_result_data)

    console.print(f'[*] All results save in {output_folder}')