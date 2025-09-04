import multiprocessing
import datetime
import sys

from progress.colors import white
from tqdm import tqdm
import argparse
from worker.process_file import *
from worker.tshark_manager import *
from output_manager.output_manager import *
from output_manager.banner import *

if __name__ == "__main__":
    print_banner()
    #Flags
    parser = argparse.ArgumentParser(prog="CredsDetect", description="Program for extracting credentials from traffic files")
    parser.add_argument('input', type=str, help='path to the file or directory containing the traffic capture files')
    parser.add_argument("-t", "--threads", type=int, help="number of threads to process")
    parser.add_argument("-n", "--name", type=str, help="name of the task to record the prefix of the result files")
    parser.add_argument("-o", "--output", type=str, help="path to the directory for results")
    parser.add_argument("-p", "--tshark_path", type=str, help="path to the TShark")
    parser.add_argument("-c", "--current", action="store_true",  help="output current results (perhaps slow down!)")
    args = parser.parse_args()
    show_machines = False #Вывод аутентификационных данных машинных учётных записей NTLM, Kerberos

    #Input files
    input_folder = ""
    input_files = []
    if os.path.isdir(args.input):
        input_folder = args.input
        for filename in os.listdir(input_folder):
            file_path = os.path.join(input_folder, filename)
            if os.path.isfile(file_path):
                input_files.append(file_path)
    else:
        if os.path.isfile(args.input):
            input_files = [args.input]
        else:
            print(f"Path {args.input} does not exist")
    #Count files
    count_files = len(input_files)
    print(f"{count_files} files were found in the directory {input_folder}")
    #Found TShark
    config_tshark = True
    config_path = "config.txt"
    if not args.tshark_path is None:
        save_tshark_config(config_path, args.tshark_path)
        print(f'Save path to TShark in config file ({args.tshark_path})')
    tshark_path = get_tshark_config(config_path)
    if (tshark_path is None) or not os.path.exists(tshark_path):
        config_tshark = False
        print('The correct path to the TShark is not specified in the configuration file')
    else:
        print(f"TShark path in config.txt {tshark_path}")
    if not config_tshark:
        tshark_version = check_tshark_installed()
        if not tshark_version is None:
            print(f"{tshark_version} detected in the environment")
        else:
            print("Tshark was not detected in the environment")
            sys.exit(1)
    #Count processes
    count_processes = min(multiprocessing.cpu_count(), len(input_files))
    if not args.threads is None:
        count_processes = min(len(input_files), args.threads)
    #Filter protocols
    default_protocols = ['kerberos',
                         'ntlmssp',
                         'http.proxy_authenticate',
                         'http.proxy_authorization',
                         'http.authorization',
                         'pop',
                         'imap',
                         'smtp',
                         'ftp']
    filter_protocols = ' or '.join(default_protocols)
    print(f'Protocol filtering is performed with "{filter_protocols}"')
    #Output folder
    output_folder = os.path.join(os.getcwd(), 'results')
    if not args.output is None:
        output_folder = args.output
    if not os.path.exists(output_folder):
        os.mkdir(output_folder)
    if not os.path.exists(output_folder):
        print('[!] Output folder not exists!')
        exit(1)
    #Taskname
    task_name = str(datetime.datetime.now()).replace(' ', '_').replace(':', '')
    if not args.name is None:
        task_name = args.name
    #Start processing
    processed_files = 0
    with multiprocessing.Manager() as manager:
        queue = manager.Queue() #use the manager to create a shared queue.
        global_result_data = [] #list with results
        shown_unique_data_id = []
        if count_processes == 0:
            print("The number of processes must be natural")
            sys.exit(1)

        print(f"{count_processes} threads have been selected for file processing")
        pool = None
        try:
            pool = multiprocessing.Pool(processes=count_processes)
            tasks = []
            for file_path in input_files:
                task = pool.apply_async(
                    process_file,
                    args=(file_path, queue, filter_protocols, tshark_path),
                    error_callback=lambda e, fp=file_path:
                    tqdm.write(f"[!] Error processing {fp}: {e}"))
                tasks.append(task)
            with tqdm(total=count_files, desc='Processing files', ncols=100) as pbar:
                timeout = 10
                while processed_files < count_files:
                    try:
                        file_path, current_results = queue.get(timeout=timeout)  # wait the chunk of results
                        if current_results == 'Started':
                            tqdm.write(f"[*] Started processing: {file_path}")
                        elif current_results == 'Done':
                            processed_files += 1  # file processing completed
                            pbar.update(1)
                            tqdm.write(f"[✓] {file_path} completed ({processed_files}/{count_files}).")
                        else:
                            global_result_data.extend(current_results)
                            if args.current:
                                show_str = print_current_results(current_results, shown_unique_data_id)
                                tqdm.write(show_str)
                            else:
                                tqdm.write(f"[+] Found {len(current_results)} packets")
                    except Exception as e:
                        if "" == str(e):
                            if all(task.ready() for task in tasks):
                                tqdm.write("[!] Timeout waiting for results, tasks done. Closing.")
                                break
                            else:
                                tqdm.write("[*] Timeout waiting for results, tasks active. Please wait...")
                        else:
                            tqdm.write(f"[!] Unexpected error: {e}")
        except Exception as e:
            tqdm.write(f"[!] Critical error: {e}")
        finally:
            tqdm.write("[*] Closing pool...")
            if pool is not None:
                pool.close()
                pool.terminate()
                pool.join()

    print('File processing completed. Post processing...\n')

    result_process = multiprocessing.Process(target=print_results, args=(output_folder, task_name, global_result_data))
    result_process.start()
    result_process.join()

    print('          ------------------------------')
    print("          | Done! Designed by @Nike417 |")
    print('          ------------------------------\n')