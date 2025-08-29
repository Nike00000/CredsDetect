def get_kerberos_data_str(packet:dict):
    if 'asreq' in packet['type']:
        func = asreq_format
    elif 'asrep' in packet['type']:
        func = asrep_format
    elif 'tgsrep' in packet['type']:
        func = tgsrep_format
    else:
        return 'unknown', 'unknown'
    return func(packet['data'])

def sort_kerberos_type(packets:list, unique, machine, hash_type):
    results = list()
    hash_id_list = list()
    packets_by_time = sorted(packets, key=lambda x: x['time'], reverse=True)
    for packet in packets_by_time:
        if not machine and '$' in packet['data']['cname']:
            continue
        if not packet['type'] == hash_type:
            continue
        hash_id, hash_data = get_kerberos_data_str(packet)
        if unique:
            if hash_id in hash_id_list:
                continue
            hash_id_list.append(hash_id)
        results.append(packet)

    return results

def asreq_format(data:dict):
    hash_data = f"$krb5pa${data['etype']}${data['cname']}${data['realm']}${data['cipher']}"
    hash_id = f"$krb5pa${data['etype']}${data['cname']}${data['realm']}"
    return hash_id, hash_data

def asrep_format(data:dict):
    hash_data = f"$krb5asrep${data['etype']}${data['cname']}@{data['realm']}:{data['cipher'][:24]}${data['cipher'][24:]}"
    hash_id = f"$krb5asrep${data['etype']}${data['cname']}@{data['realm']}"
    return hash_id, hash_data

def tgsrep_format(data:dict):
    hash_id = f"$krb5tgs${data['etype']}$*{data['cname']}${data['realm']}"
    if data['etype'] == 23:
        hash_data = f"$krb5tgs${data['etype']}$*{data['cname']}${data['realm']}${data['sname']}*${data['cipher'][:32]}${data['cipher'][32:]}"
    else:
        hash_data = f"$krb5tgs${data['etype']}${data['sname']}${data['realm']}${data['cipher'][:24]}${data['cipher'][24:]}"
    return hash_id, hash_data