def extract_netntlmv2(netntlm_data: dict, unique, machine):
    results = list()
    results_dict = dict()
    for tcpID in netntlm_data.keys():
        sorted_ntlm_list = sorted(netntlm_data[tcpID], key=lambda x: x['pnum'])
        challenge = None
        for ntlm_packet in sorted_ntlm_list:
            if ntlm_packet['type'] == 2:
                challenge = ntlm_packet["challenge"]
            if ntlm_packet['type'] == 3:
                if challenge is None:
                    continue
                user = ntlm_packet['username']
                if not machine and '$' in user:
                    challenge = None
                    continue
                if len(ntlm_packet['domain']):
                    user += f"@{ntlm_packet['domain']}"
                if len(ntlm_packet['nt_response']) == 0:
                    continue
                ntlmv2_format = f"{ntlm_packet['username']}::{ntlm_packet['domain']}:{challenge}:{ntlm_packet['nt_response'][:32]}:{ntlm_packet['nt_response'][32:]}"
                id = f"{user}::{ntlm_packet['domain']}" #['workstation']?
                if unique:
                    results_dict[id] = ntlmv2_format
                else:
                    results.append(ntlmv2_format)
                challenge = None
    if unique:
        for key in results_dict.keys():
            results.append(results_dict[key])
    return results