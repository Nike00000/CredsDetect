import os.path
import csv
from output_manager.formatters.basic_formatter import find_basic_packet, sort_basic_type
from output_manager.formatters.kerberos_formatter import sort_kerberos_type, get_kerberos_data_str
from output_manager.formatters.ntlm_formatter import get_ntlm_data_str, find_ntlm_packet, sort_ntlm_type
from output_manager.formatters.basic_formatter import get_basic_data_str

from tabulate import tabulate

def get_cred_data_str(packet):
    match packet['auth']:
        case 'Kerberos':
            data_id, data_str = get_kerberos_data_str(packet)
        case 'NetNTLM':
            data_id, data_str = get_ntlm_data_str(packet)
        case 'ClearText':
            data_id, data_str = get_basic_data_str(packet)
        case _:  # This is the default case
            return 'unknown', 'unknown'
    return data_id, data_str

def sort_packets_by_key(packets, key):
    sorted_packets_dict = dict()
    for packet in packets:
        key_value = packet.get(key,"")
        sorted_packets_dict.setdefault(key_value,[]).append(packet)
    return sorted_packets_dict

def print_results(folder:str, task_name:str, packets:list):
    task_folder = os.path.join(folder, task_name)
    if not os.path.exists(task_folder):
        os.mkdir(task_folder)
    if not os.path.exists(task_folder):
        return

    find_all_results = list()
    find_unique_results = list()

    sorted_by_auth_packets = sort_packets_by_key(packets, 'auth')

    kerberos_packets = sorted_by_auth_packets.get('Kerberos', [])

    kerberos_types = ['asreq', 'asrep', 'tgsrep']
    kerberos_hashcat_types = {'asreq_17': '19800',
                              'asreq_18': '19900',
                              'asreq_23': '7500',
                              'asrep_23': '18200',
                              'tgsrep_17': '19600',
                              'tgsrep_18': '19700',
                              'tgsrep_23': '13100'}
    kerberos_etypes = [17, 18, 23]

    hashes_tab_list = list()

    for kerberos_type in kerberos_types:
        for kerberos_etype in kerberos_etypes:
            hash_type = f"{kerberos_type}_{kerberos_etype}"
            all_krb_hashes = sort_kerberos_type(kerberos_packets, False, True, hash_type)
            users_krb_hashes = sort_kerberos_type(kerberos_packets, False, False, hash_type)
            unique_krb_hashes = sort_kerberos_type(kerberos_packets, True, False, hash_type)
            hashcat_type = kerberos_hashcat_types.get(hash_type, 'no')
            #write in file
            write_in_file(unique_krb_hashes, f"{task_name}_{hash_type}_m_{hashcat_type}.txt", task_folder)
            write_in_file(all_krb_hashes,f"{task_name}_all_{hash_type}_m_{hashcat_type}.txt", task_folder)
            #statistic
            hashes_tab_list.append(['Kerberos',
                                    hash_type,
                                    len(unique_krb_hashes),
                                    len(users_krb_hashes),
                                    len(all_krb_hashes),
                                    hashcat_type])
            find_all_results.extend(all_krb_hashes)
            find_unique_results.extend(unique_krb_hashes)

    ntlm_packets = sorted_by_auth_packets.get('NetNTLM', [])
    sorted_by_session_ntlm_dict = sort_packets_by_key(ntlm_packets, 'session_id')
    join_ntlm_packets = find_ntlm_packet(sorted_by_session_ntlm_dict)
    ntlm_types = ['hash_v1','hash_v2','lm_response']
    ntlm_types_dict = {'hash_v1': '5500',
                       'hash_v2': '5600'}
    for ntlm_type in ntlm_types:
        all_ntlm_hashes = sort_ntlm_type(join_ntlm_packets, False, True, ntlm_type)
        users_ntlm_hashes = sort_ntlm_type(join_ntlm_packets, False, False, ntlm_type)
        unique_ntlm_hashes = sort_ntlm_type(join_ntlm_packets, True, False, ntlm_type)
        hashcat_type = ntlm_types_dict.get(ntlm_type, 'no')
        # write in file
        write_in_file(unique_ntlm_hashes, f"{task_name}_{ntlm_type}_m_{hashcat_type}.txt", task_folder)
        write_in_file(all_ntlm_hashes, f"{task_name}_all_{ntlm_type}_m_{hashcat_type}.txt", task_folder)
        #statistic
        hashes_tab_list.append(['NetNTLM',
                                ntlm_type,
                                len(unique_ntlm_hashes),
                                len(users_ntlm_hashes),
                                len(all_ntlm_hashes),
                                hashcat_type])
        find_all_results.extend(all_ntlm_hashes)
        find_unique_results.extend(unique_ntlm_hashes)

    print(tabulate(hashes_tab_list, headers=['protocol', 'type', 'unique', 'users', 'all', 'hashcat']))
    print()

    clear_text_packets = sorted_by_auth_packets.get('ClearText', [])
    sorted_by_session_ct_dict = sort_packets_by_key(clear_text_packets, 'session_id')
    join_clear_text_packets = find_basic_packet(sorted_by_session_ct_dict)
    ct_protocols = ['FTP',
                    'POP',
                    'IMAP',
                    'SMTP',
                    'HTTP.ProxyAuthenticate',
                    'HTTP.ProxyAuthorization',
                    'HTTP.Authorization']
    ct_tab_list = list()
    for protocol in ct_protocols:
        all_ct_str = sort_basic_type(join_clear_text_packets, False, protocol)
        unique_ct_str = sort_basic_type(join_clear_text_packets, True, protocol)
        ct_tab_list.append([protocol,
                                len(unique_ct_str),
                                len(all_ct_str)])
        find_all_results.extend(all_ct_str)
        find_unique_results.extend(unique_ct_str)
    print(tabulate(ct_tab_list, headers=['protocol', 'unique', 'all']))
    print()

    write_to_csv(find_unique_results, 'unique_results.csv', task_folder)
    write_to_csv(find_all_results, 'all_results.csv', task_folder)

    print(f'All results save in {task_folder}\n\n')

def write_in_file(packets, filename, folder):
    if packets is None:
        return
    if len(packets) == 0:
        return
    file_path = os.path.join(folder, filename)
    data_strs = []
    for packet in packets:
        data_key, data_str = get_cred_data_str(packet)
        data_strs.append(data_str)
    data_strs.sort()
    file = open(file_path, 'w', encoding='utf-8')
    for sort_data_str in data_strs:
        file.write(sort_data_str + '\n')
    file.close()
    return

def write_to_csv(packets:list, filename:str, folder:str):

    file_path = os.path.join(folder, filename)
    with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile, delimiter='\t')

        writer.writerow(['Filename',
                         'Source',
                         'Destination',
                         'Protocol',
                         'Auth',
                         'Type',
                         'Data'])
        for packet in packets:
            data_key, data_str = get_cred_data_str(packet)
            row = [packet.get('filename'),
                   f"{packet.get('src_ip')}:{packet.get('src_port')}",
                   f"{packet.get('dst_ip')}:{packet.get('dst_port')}",
                   packet.get('protocol'),
                   packet.get('auth'),
                   packet.get('type'),
                   data_str]
            writer.writerow(row)

def print_current_results(current_results, shown_unique_data_id):
    show_str = ""
    skip_counter = 0
    for packet in current_results:
        data_id, cred_data = get_cred_data_str(packet)
        if data_id in shown_unique_data_id:
            skip_counter += 1
            continue
        shown_unique_data_id.append(data_id)
        show_str += f"[+] In {packet['protocol']} found {packet['auth']} "
        show_str += f"{packet['type']} ({packet['src_ip']} -> {packet['dst_ip']})"
        show_str += f"\n{cred_data}\n"

    if skip_counter > 0:
        show_str += f"[*] Skipped {skip_counter} duplicate entries"

    return show_str