def extract_ftp(creds, unique):
    results = []
    if creds is None:
        return []
    for cred in creds:
        src_ip = cred['src'].split(':')[0]
        dst_ip = cred['dst'].split(':')[0]
        results.append([src_ip, dst_ip, cred['user'], cred['pass']])
    if unique:
        unique_results = []
        for one in results:
            has = False
            for unique_one in unique_results:
                if one[2] == unique_one[2] and one[3] == unique_one[3]:
                    if one[1] == unique_one[1]:
                        has = True
            if not has:
                unique_results.append(one)
        return unique_results
    return results