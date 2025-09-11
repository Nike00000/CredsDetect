def find_ntlm_packet(sorted_ntlm_dict: dict):
    results = list()

    for session_id in sorted_ntlm_dict.keys():
        sorted_ntlm_list = sorted(sorted_ntlm_dict[session_id], key=lambda x: x['time'])
        challenge = None
        for ntlm_packet in sorted_ntlm_list:
            if 'challenge' in ntlm_packet['type']:
                challenge = ntlm_packet['data']['challenge']
            elif 'nt_response' in ntlm_packet['type']:
                if challenge is None:
                    continue
                ntlm_packet['data']['challenge'] = challenge
                ntlm_packet['type'] = f'hash_{ntlm_packet['type'].split('_')[-1]}'
                results.append(ntlm_packet)
                if ntlm_packet['data']['lm_response'] != '000000000000000000000000000000000000000000000000':
                    lm_packet = ntlm_packet.copy()
                    lm_packet['type'] = 'lm_response'
                    results.append(lm_packet)
    return results

def sort_ntlm_type(ntlm_packets: list, unique, machine, hash_type):
    results = list()
    unique_key_list = list()
    ntlm_packets_by_time = sorted(ntlm_packets, key=lambda x: x['time'], reverse=True)
    for ntlm_packet in ntlm_packets_by_time:
        if hash_type != ntlm_packet['type']:
            continue
        if not machine:
            if '$' in ntlm_packet['data']['username']:
                continue
        data_id, data_str = get_ntlm_data_str(ntlm_packet)
        if unique:
            if data_id in unique_key_list:
               continue
            unique_key_list.append(data_id)
        results.append(ntlm_packet)
    return results

def get_ntlm_data_str(packet:dict):
    data = packet['data']
    key, text = 'unknown', 'unknown'
    if 'challenge' in packet['type']:
        key = packet['session_id']+packet['type']
        text = f"challenge: {data['challenge']}"
        return key.lower(), text
    key = f"{data['username']}@{data['domain'].split('.')[0]}{packet['type']}"
    if 'nt_response' in packet['type']:
        text = f"username: {data['username']}\nlm_response: {data['lm_response']}\nnt_response: {data['nt_response']}"
    elif 'hash_v2' in packet['type']:
        text_username = f"{data['username']}@{data['domain']}"
        text = f"{text_username}:{data['challenge']}:{data['nt_response'][:32]}:{data['nt_response'][32:]}"
    elif 'hash_v1' in packet['type']:
        text_username = f"{data['username']}@{data['domain']}"
        text = f"{text_username}:{data['lm_response']}:{data['nt_response']}:{data['challenge']}"
    elif 'lm_response' in packet['type']:
        text = f"{data['lm_response']}"

    return key.lower(), text