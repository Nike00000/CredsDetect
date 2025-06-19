def extract_asreq(as_req_data:list, unique, machine, etype):
    results = list()
    results_dict = dict()
    for as_req in as_req_data:
        if not machine and '$' in as_req['cname']:
            continue
        if not etype == as_req['etype']:
            continue
        asreq_format = f"$krb5pa${as_req['etype']}${as_req['cname']}${as_req['realm']}${as_req['cipher']}"
        if unique:
            asreq_id = f"$krb5pa${as_req['etype']}${as_req['cname']}${as_req['realm']}"
            results_dict[asreq_id] = asreq_format
        else:
            results.append(asreq_format)

    if unique:
        for key in results_dict.keys():
            results.append(results_dict[key])
    return results

def extract_asrep(hashes:list, unique, machine, etype):
    results = list()
    results_dict = dict()
    for hash in hashes:
        if not machine and '$' in hash['cname']:
            continue
        if not etype == hash['etype']:
            continue
        hash_in_format = asrep_format(hash)
        if unique:
            hash_id = f"$krb5asrep${hash['etype']}${hash['cname']}@{hash['realm']}"
            results_dict[hash_id] = hash_in_format
        else:
            results.append(hash_in_format)

    if unique:
        for key in results_dict.keys():
            results.append(results_dict[key])
    return results

def extract_tgsrep(hashes:list, unique, machine, etype):
    results = list()
    results_dict = dict()
    for hash in hashes:
        if not machine and '$' in hash['cname']:
            continue
        if not etype == hash['etype']:
            continue
        hash_in_format = tgsrep_format(hash)
        if unique:
            hash_id = f"$krb5tgs${hash['etype']}$*{hash['cname']}${hash['realm']}"
            results_dict[hash_id] = hash_in_format
        else:
            results.append(hash_in_format)

    if unique:
        for key in results_dict.keys():
            results.append(results_dict[key])
    return results

def asreq_format(as_rep):
    return f"$krb5pa${as_rep['etype']}${as_rep['cname']}${as_rep['realm']}${as_rep['cipher']}"

def asrep_format(as_rep):
    return f"$krb5asrep${as_rep['etype']}${as_rep['cname']}@{as_rep['realm']}:{as_rep['cipher'][:24]}${as_rep['cipher'][24:]}"

def tgsrep_format(tgs_rep):
    if tgs_rep['etype'] == 23:
        return f"$krb5tgs${tgs_rep['etype']}$*{tgs_rep['cname']}${tgs_rep['realm']}${tgs_rep['sname']}*${tgs_rep['cipher'][:32]}${tgs_rep['cipher'][32:]}"
    else:
        return f"$krb5tgs${tgs_rep['etype']}${tgs_rep['sname']}${tgs_rep['realm']}${tgs_rep['cipher'][:24]}${tgs_rep['cipher'][24:]}"
