import os.path

from output_manager.formatters.http_formatter import extract_http_auth_basic
from output_manager.formatters.kerberos_formatter import *
from output_manager.formatters.ntlm_formatter import *
from output_manager.formatters.pop_formatter import *
from output_manager.formatters.imap_formatter import *
from output_manager.formatters.smtp_formatter import *
from tabulate import tabulate

def print_hashes(hashes, name, hashcat):
    if len(hashes) > 0:
        print(f"Found {len(hashes)} {name} hashes (hashcat type {hashcat})")
        for hash_one in hashes:
            print(hash_one)
        print()

def print_results(folder, task_name, results):

    asreq17_all = extract_asreq(results['asreq'], False, True, 17)
    asreq17_users = extract_asreq(results['asreq'], False, False, 17)
    asreq17_unique = extract_asreq(results['asreq'], True, False, 17)
    asreq18_all = extract_asreq(results['asreq'], False, True, 18)
    asreq18_users = extract_asreq(results['asreq'], False, False, 18)
    asreq18_unique = extract_asreq(results['asreq'], True, False, 18)
    asreq23_all = extract_asreq(results['asreq'], False, True, 23)
    asreq23_users = extract_asreq(results['asreq'], False, False, 23)
    asreq23_unique = extract_asreq(results['asreq'], True, False, 23)

    asrep17_all = extract_asrep(results['asrep'], False, True, 17)
    asrep17_users = extract_asrep(results['asrep'], False, False, 17)
    asrep17_unique = extract_asrep(results['asrep'], True, False, 17)
    asrep18_all = extract_asrep(results['asrep'], False, True, 18)
    asrep18_users = extract_asrep(results['asrep'], False, False, 18)
    asrep18_unique = extract_asrep(results['asrep'], True, False, 18)
    asrep23_all = extract_asrep(results['asrep'], False, True, 23)
    asrep23_users = extract_asrep(results['asrep'], False, False, 23)
    asrep23_unique = extract_asrep(results['asrep'], True, False, 23)

    tgsrep17_all = extract_tgsrep(results['tgsrep'], False, True, 17)
    tgsrep17_users = extract_tgsrep(results['tgsrep'], False, False, 17)
    tgsrep17_unique = extract_tgsrep(results['tgsrep'], True, False, 17)
    tgsrep18_all = extract_tgsrep(results['tgsrep'], False, True, 18)
    tgsrep18_users = extract_tgsrep(results['tgsrep'], False, False, 18)
    tgsrep18_unique = extract_tgsrep(results['tgsrep'], True, False, 18)
    tgsrep23_all = extract_tgsrep(results['tgsrep'], False, True, 23)
    tgsrep23_users = extract_tgsrep(results['tgsrep'], False, False, 23)
    tgsrep23_unique = extract_tgsrep(results['tgsrep'], True, False, 23)

    ntlm_all = extract_netntlmv2(results['netntlmv2'], False, True)
    ntlm_users = extract_netntlmv2(results['netntlmv2'], False, False)
    ntlm_unique = extract_netntlmv2(results['netntlmv2'], True, False)

    # Print results
    print_hashes(ntlm_unique, 'NetNTLM  unique users', 5600)
    print_hashes(asreq17_unique, 'asreq17 unique users', 19800)
    print_hashes(asreq18_unique, 'asreq18 unique users', 19900)
    print_hashes(asreq23_unique, 'asreq23 unique users', 7500)
    print_hashes(asrep17_unique, 'asrep17 unique users', '-')
    print_hashes(asrep18_unique, 'asrep18 unique users', '-')
    print_hashes(asrep23_unique, 'asrep23 unique users', 18200)
    print_hashes(tgsrep17_unique, 'tgsrep17 unique users', 19600)
    print_hashes(tgsrep18_unique, 'tgsrep18 unique users', 19700)
    print_hashes(tgsrep23_unique, 'tgsrep23 unique users', 13100)

    # Write unique results
    write_in_file(ntlm_unique, f"{task_name}_netNTLM_m5600.txt", folder)
    write_in_file(asreq17_unique, f"{task_name}_asreq17_m19800.txt", folder)
    write_in_file(asreq18_unique, f"{task_name}_asreq18_m19900.txt", folder)
    write_in_file(asreq23_unique, f"{task_name}_asreq23_m7500.txt", folder)
    write_in_file(asrep17_unique, f"{task_name}_asrep17.txt", folder)
    write_in_file(asrep18_unique, f"{task_name}_asrep18.txt", folder)
    write_in_file(asrep23_unique, f"{task_name}_asrep23_m18200.txt", folder)
    write_in_file(tgsrep17_unique, f"{task_name}_tgsrep17_m19600.txt", folder)
    write_in_file(tgsrep18_unique, f"{task_name}_tgsrep18_m19700.txt", folder)
    write_in_file(tgsrep23_unique, f"{task_name}_tgsrep23_m13100.txt", folder)

    # Write all results
    write_in_file(ntlm_all, f"{task_name}_all_netNTLM_m5600.txt", folder)
    write_in_file(asreq17_all, f"{task_name}_all_asreq17_m19800.txt", folder)
    write_in_file(asreq18_all, f"{task_name}_all_asreq18_m19900.txt", folder)
    write_in_file(asreq23_all, f"{task_name}_all_asreq23_m7500.txt", folder)
    write_in_file(asrep17_all, f"{task_name}_all_asrep17.txt", folder)
    write_in_file(asrep18_all, f"{task_name}_all_asrep18.txt", folder)
    write_in_file(asrep23_all, f"{task_name}_all_asrep23_m18200.txt", folder)
    write_in_file(tgsrep17_all, f"{task_name}_all_tgsrep17_m19600.txt", folder)
    write_in_file(tgsrep18_all, f"{task_name}_all_tgsrep18_m19700.txt", folder)
    write_in_file(tgsrep23_all, f"{task_name}_all_tgsrep23_m13100.txt", folder)

    list_hashes_tab = [['asreq17', len(asreq17_unique), len(asreq17_users), len(asreq17_all), 19800],
                ['asreq18', len(asreq18_unique), len(asreq18_users), len(asreq18_all), 19900],
                ['asreq23', len(asreq23_unique), len(asreq23_users), len(asreq23_all), 7500],
                ['asrep17', len(asrep17_unique), len(asrep17_users), len(asrep17_all), '-'],
                ['asrep18', len(asrep18_unique), len(asrep18_users), len(asrep18_all), '-'],
                ['asrep23', len(asrep23_unique), len(asrep23_users), len(asrep23_all), 18200],
                ['tgsrep17', len(tgsrep17_unique), len(tgsrep17_users), len(tgsrep17_all), 19600],
                ['tgsrep18', len(tgsrep18_unique), len(tgsrep18_users), len(tgsrep18_all), 19700],
                ['tgsrep23', len(tgsrep23_unique), len(tgsrep23_users), len(tgsrep23_all), 13100],
                ['NetNTLM', len(ntlm_unique), len(ntlm_users), len(ntlm_all), 5600]]

    print(tabulate(list_hashes_tab, headers=['type', 'unique', 'users', 'all', 'hashcat']))
    print()

    #Write POP
    pop_creds = extract_pop3(results['pop3'], True)
    if len(pop_creds):
        print(f"Found {len(pop_creds)} unique POP credentials")
        print(tabulate(pop_creds, headers=['src', 'dst', 'user', 'pass']))
        print()
        write_in_file_tabulate(pop_creds, ['src', 'dst','user','pass'],
                               f"{task_name}_pop.txt", folder)


    #Write IMAP
    imap_creds = extract_imap(results['imap'], True)
    if len(imap_creds):
        print(f"Found {len(imap_creds)} unique IMAP credentials")
        print(tabulate(imap_creds, headers=['src', 'dst', 'user', 'pass']))
        print()
        write_in_file_tabulate(imap_creds, ['src', 'dst', 'user', 'pass'],
                               f"{task_name}_imap.txt", folder)


    #Write SMTP
    smtp_creds = extract_smtp(results['smtp'], True)
    if len(smtp_creds):
        print(f"Found {len(smtp_creds)} unique SMTP credentials")
        print(tabulate(smtp_creds, headers=['src', 'dst', 'user', 'pass']))
        print()
        write_in_file_tabulate(smtp_creds, ['src', 'dst', 'user', 'pass'],
                               f"{task_name}_smtp.txt", folder)

        print(f'All results saved in {folder}\n')

    # Write HTTP
    http_creds = extract_http_auth_basic(results['http_authbasic'], True)
    if len(http_creds):
        headers = ['src', 'dst', 'user', 'pass', 'uri']
        print(f"Found {len(http_creds)} unique HTTP basic authentication")
        print(tabulate(http_creds, headers=headers))
        print()
        write_in_file_tabulate(http_creds, headers,f"{task_name}_http_authbasic.txt", folder)

        print(f'All results saved in {folder}\n')

def write_in_file_tabulate(lists, headers, filename, folder = os.getcwd()):
    if lists is None:
        return
    if len(lists) == 0:
        return
    if not os.path.exists(folder):
        os.mkdir(folder)
    if not os.path.exists(folder):
        folder = os.getcwd()
        os.mkdir(folder)
    file_path = os.path.join(folder,filename)
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(tabulate(lists, headers=headers))
    return

def write_in_file(lines, filename, folder = os.getcwd()):
    if lines is None:
        return
    if len(lines) == 0:
        return
    if not os.path.exists(folder):
        os.mkdir(folder)
    if not os.path.exists(folder):
        folder = os.getcwd()
        os.mkdir(folder)
    file_path = os.path.join(folder,filename)
    file = open(file_path, 'w', encoding='utf-8')
    for line in lines:
        file.write(line + '\n')
    file.close()
    return

