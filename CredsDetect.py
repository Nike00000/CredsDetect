import multiprocessing
import datetime
import os.path
import sys

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
    default_protocols = ['kerberos', 'ntlmssp', 'pop', 'imap', 'smtp', 'http.authbasic']
    filter_protocols = ' or '.join(default_protocols)
    print(f'Protocol filtering is performed with "{filter_protocols}"')
    #Output folder
    output_folder = os.path.join(os.getcwd(), 'results')
    if not args.output is None:
        output_folder = args.output
    #Taskname
    task_name = str(datetime.datetime.now()).replace(' ', '_').replace(':', '')
    if not args.name is None:
        task_name = args.name
    #Start processing
    processed_files = 0
    with multiprocessing.Manager() as manager:
        queue = manager.Queue() #use the manager to create a shared queue.
        results = dict_results() #dict with results
        if count_processes == 0:
            print("The number of processes must be natural")
            sys.exit(1)

        print(f"{count_processes} threads have been selected for file processing")
        with multiprocessing.Pool(processes=count_processes) as pool:
            #Создание пула задач обработки
            if config_tshark:
                for file_path in input_files:
                    pool.apply_async(process_file, args=(file_path, queue, filter_protocols, tshark_path))
            else:
                for file_path in input_files:
                    pool.apply_async(process_file, args=(file_path, queue, filter_protocols))
            #Обработка промежуточных результатов

            with tqdm(total=count_files, desc='Processing files', ncols=100) as pbar:
                while processed_files < count_files:
                    file_path, current_results = queue.get()  # wait the chunk of results
                    if current_results == 'Done':
                        processed_files += 1  # file processing completed
                        pbar.update(1)
                        tqdm.write(f"[+] {file_path} completed ({processed_files}/{count_files}).")
                    else:
                        merge_dict_results(results, current_results)  # add chunk to common results
                        for key in current_results.keys():
                            if len(current_results[key]):
                                tqdm.write(f"{file_path}: added {len(current_results[key])} {key} packets")
            pool.close()
            pool.join()

    print('File processing completed. Post processing...\n')

    process_result = multiprocessing.Process(target=print_results,args=(output_folder, task_name, results))
    process_result.start()
    process_result.join()

    print('          ------------------------------')
    print("          | Done! Designed by @Nike417 |")
    print('          ------------------------------\n')