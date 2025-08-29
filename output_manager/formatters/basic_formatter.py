def get_basic_data_str(packet:dict):
    data_str = ""
    data_id = f"{packet['dst_ip']}-{packet['protocol']}"
    if 'user' == packet['type']:
        data_str = f"{packet['data']['user']}"
    elif "pass" == packet['type']:
        data_str = f"{packet['data']['pass']}"
    elif "user:pass" in packet['type']:
        data_str = f"{packet['data']['user']} : {packet['data']['pass']}"
    return f"{data_id}-{data_str}", data_str

def find_basic_packet(sorted_ct_dict: dict):
    results = list()

    for session_id in sorted_ct_dict.keys():
        sorted_list = sorted(sorted_ct_dict[session_id], key=lambda x: x['time'])
        user_packet = None
        for packet in sorted_list:
            if packet['type'] == 'user':
                if not user_packet is None:
                    results.append(user_packet)
                user_packet = packet
            elif packet['type'] == 'pass':
                if user_packet is None:
                    continue
                packet['data']['user'] = user_packet['data']['user']
                packet['type'] = 'user:pass'
                results.append(packet)
            elif packet['type'] == 'user:pass':
                results.append(packet)
    return results

def sort_basic_type(packets: list, unique, protocol):
    results = list()
    unique_key_list = list()
    for packet in packets:

        if packet['protocol'] != protocol:
            continue
        data_id, data_str = get_basic_data_str(packet)
        if unique:
            if data_id in unique_key_list:
               continue
            unique_key_list.append(data_id)
        results.append(packet)
    return results