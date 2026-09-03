import os.path
import csv
from containers.results_container import ResultsContainer
from containers.unique_container import UniqueContainer
from dto.enums import KerberosEtypeEnum, NTLMResponseEnum
from dto.base_data import BaseData
from dto.user_pass_data import UserPassData
from dto.enums import UserPassProtocolEnum
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

def print_unique_container(container:UniqueContainer, folder:str, task_name:str, name: str):
    hashcat_type = hashcat_types[name]
    all_data = container.all
    users_data = container.users
    unique_data = container.unique
    write_in_file(all_data, f"all.{name}.{task_name}.txt", folder)
    write_in_file(users_data, f"users.{name}.{task_name}.txt", folder)
    write_in_file(unique_data, f"unique.{name}.{task_name}.txt", folder)

def print_kerberos(results:ResultsContainer, folder:str, task_name:str):
    for etype in KerberosEtypeEnum:
        print_unique_container(container=results.kerberos_container.asreq[etype],
                               folder=folder,
                               task_name=task_name,
                               name=f'asreq_{etype.value}')
        print_unique_container(container=results.kerberos_container.asrep[etype],
                               folder=folder,
                               task_name=task_name,
                               name=f'asrep_{etype.value}')
        print_unique_container(container=results.kerberos_container.tgsrep[etype],
                               folder=folder,
                               task_name=task_name,
                               name=f'tgsrep_{etype.value}')
    

def print_ntlm(results:ResultsContainer, folder:str, task_name:str):
    for ntlm_type in NTLMResponseEnum:
        print_unique_container(container=results.ntlm_container.get_hash(ntlm_type),
                               folder=folder,
                               task_name=task_name,
                               name=f'ntlm_{ntlm_type.value}')
        
    

def print_results(task_folder:str, task_name:str, results:ResultsContainer):
    all_results = []

    userpass_data = results.user_pass_container.get_all()
    for protocol in userpass_data.keys():
        if not len(userpass_data[protocol].unique):
            continue
        write_to_csv(data_list=userpass_data[protocol].unique,
                     filename=f"unique.{protocol.value}.{task_name}.csv".lower(),
                     folder=task_folder)
        write_to_csv(data_list=userpass_data[protocol].all,
                     filename=f"all.{protocol.value}.{task_name}.csv".lower(),
                     folder=task_folder)
        all_results.extend(userpass_data[protocol].all)

    #Print results
    print_kerberos(results=results,
                   folder=task_folder,
                   task_name=task_name)

    print_ntlm(results=results,
                folder=task_folder,
                task_name=task_name)

    all_results.extend(results.kerberos_container.get_all())
    all_results.extend(results.ntlm_container.get_all())

    write_to_csv(data_list=all_results,
                 filename=f"all.{task_name}.csv".lower(),
                 folder=task_folder)
    

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
            row = [data.filename,
                   f"{data.src_ip}:{data.src_port}",
                   f"{data.dst_ip}:{data.dst_port}",
                   data.protocol(),
                   data.authentication_protocol,
                   data.name,
                   data.data()]
            writer.writerow(row)