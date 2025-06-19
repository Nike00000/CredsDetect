def extract_pop3(pop3_results: dict, unique):
    results = []
    for tcpID in pop3_results.keys():
        sorted_list = sorted(pop3_results[tcpID], key=lambda x: x['pnum'])
        login = ''
        for packet in sorted_list:
            if packet['command'] == 'user':
                login = packet['parameter']
            if packet['command'] == 'pass':
                src_ip = packet['src'].split(':')[0]
                dst_ip = packet['dst'].split(':')[0]
                creds = [src_ip, dst_ip, login, packet['parameter']]
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