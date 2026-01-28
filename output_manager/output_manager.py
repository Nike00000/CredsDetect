import os.path
import csv
from containers.results_container import ResultsContainer
from containers.unique_container import UniqueContainer
from dto.enums import KerberosEtypeEnum, NTLMResponseEnum
from dto.base_data import BaseData

hashcat_types = {'asreq_17': '19800',
                 'asreq_18': '19900',
                 'asreq_23': '7500',
                 'asrep_23': '18200',
                 'asrep_17': '32100',
                 'asrep_18': '32200',
                 'tgsrep_17': '19600',
                 'tgsrep_18': '19700',
                 'tgsrep_23': '13100',
                 f'ntlm_{NTLMResponseEnum.RESPONSE_V1.value}': '5500',
                 f'ntlm_{NTLMResponseEnum.RESPONSE_V2.value}': '5600'
                 }

def print_unique_container(container:UniqueContainer, folder:str, users_folder: str, all_folder: str, task_name:str, name: str):
    hashcat_type = hashcat_types[name]
    all_data = container.all
    users_data = container.users
    unique_data = container.unique
    write_in_file(all_data, f"{task_name}_{name}_all__m_{hashcat_type}.txt", all_folder)
    write_in_file(users_data, f"{task_name}_{name}_users__m_{hashcat_type}.txt", users_folder)
    write_in_file(unique_data, f"{task_name}_{name}_unique__m_{hashcat_type}.txt", folder)

def print_kerberos(results:ResultsContainer, folder:str, users_folder: str, all_folder: str, task_name:str):
    for etype in KerberosEtypeEnum:
        print_unique_container(container=results.kerberos_container.asreq[etype],
                               folder=folder,
                               users_folder=users_folder,
                               all_folder=all_folder,
                               task_name=task_name,
                               name=f'asreq_{etype.value}')
        print_unique_container(container=results.kerberos_container.asrep[etype],
                               folder=folder,
                               users_folder=users_folder,
                               all_folder=all_folder,
                               task_name=task_name,
                               name=f'asrep_{etype.value}')
        print_unique_container(container=results.kerberos_container.tgsrep[etype],
                               folder=folder,
                               users_folder=users_folder,
                               all_folder=all_folder,
                               task_name=task_name,
                               name=f'tgsrep_{etype.value}')
    

def print_ntlm(results:ResultsContainer, folder:str, users_folder: str, all_folder: str, task_name:str):
    for ntlm_type in NTLMResponseEnum:
        print_unique_container(container=results.ntlm_container.get_hash(ntlm_type),
                               folder=folder,
                               users_folder=users_folder,
                               all_folder=all_folder,
                               task_name=task_name,
                               name=f'ntlm_{ntlm_type.value}')
        
    

def print_results(task_folder:str, task_name:str, results:ResultsContainer):
    #Create Users folder
    users_task_folder = os.path.join(task_folder, 'users')
    if not os.path.exists(users_task_folder):
        os.mkdir(users_task_folder)
    if not os.path.exists(users_task_folder):
        return
    #Create All folder
    all_task_folder = os.path.join(task_folder, 'all')
    if not os.path.exists(all_task_folder):
        os.mkdir(all_task_folder)
    if not os.path.exists(all_task_folder):
        return
    #Print results
    print_kerberos(results=results,
                   folder=task_folder,
                   users_folder=users_task_folder,
                   all_folder=all_task_folder,
                   task_name=task_name)

    print_ntlm(results=results,
                folder=task_folder,
                users_folder=users_task_folder,
                all_folder=all_task_folder,
                task_name=task_name)


    all_results = results.get_all()

    write_to_csv(all_results, f'all_results_{task_name}.csv', all_task_folder)

def write_in_file(packets: list[BaseData], filename, folder):
    if packets is None:
        return
    if len(packets) == 0:
        return
    file_path = os.path.join(folder, filename)
    data_strs = []
    for packet in packets:
        data_str = packet.data()
        data_strs.append(data_str)
    data_strs.sort()
    file = open(file_path, 'w', encoding='utf-8')
    for sort_data_str in data_strs:
        file.write(sort_data_str + '\n')
    file.close()
    return

def write_to_csv(data_list:list[BaseData], filename:str, folder:str):

    file_path = os.path.join(folder, filename)
    with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile, delimiter='\t')

        writer.writerow(['Filename',
                         'Source',
                         'Destination',
                         'Protocol',
                         'Auth',
                         'Name',
                         'Data'])
        for data in data_list:
            data_str = data.data()
            row = [data.filename,
                   f"{data.src_ip}:{data.src_port}",
                   f"{data.dst_ip}:{data.dst_port}",
                   data.protocol(),
                   data.authentication_protocol,
                   data.name,
                   data_str]
            writer.writerow(row)