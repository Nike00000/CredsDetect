def extract_ftp(ftp_dict, unique):
    results = []
    for tcpID in ftp_dict.keys():
        sorted_list = sorted(ftp_dict[tcpID], key=lambda x: x['pnum'])
        login = ''
        for packet in sorted_list:
            if packet['command'] == 'user':
                login = packet['arg']
            if packet['command'] == 'pass':
                src_ip = packet['src'].split(':')[0]
                dst_ip = packet['dst'].split(':')[0]
                creds = [src_ip, dst_ip, login, packet['arg']]
                results.append(creds)
                login = ''
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