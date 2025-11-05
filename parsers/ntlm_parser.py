def find_int(data_bytes, position, length):
    value_raw = data_bytes[position:(position + length)]
    return int.from_bytes(value_raw, 'little')

def find_str(data_bytes, position, length):
    return data_bytes[position: (position + length)].hex()

def find_bin(data_bytes, position, length):
    value_int = find_int(data_bytes, position, length)
    return format(value_int, f'0>{length}b')

def find_word(data_bytes, length_position, length_size, offset_position, offset_size):
    length = find_int(data_bytes, length_position, length_size)
    offset = find_int(data_bytes, offset_position, offset_size)
    word = find_str(data_bytes, offset, length)
    return word

def decode_word(data_bytes, length_position, length_size, offset_position, offset_size):
    length = find_int(data_bytes, length_position, length_size)
    offset = find_int(data_bytes, offset_position, offset_size)
    word = data_bytes[offset: (offset + length)].decode('utf-16')
    return word

def ntlm_tcp_payload_parse(packet):
    try:
        payload = packet['tcp']['tcp_tcp_payload']
        payload_str = str(payload).replace(':', '')
        ntlm_type, ntlm_data = ntlm_parse(payload_str)
        if ntlm_type is None or ntlm_data is None:
            return None, None, None, None
        return 'TCP', 'NetNTLM', ntlm_type, ntlm_data
    except:
        return None, None, None, None

def ntlm_parse(payload_str):
    try:
        data = dict()
        ntlmssp_signature = "4e544c4d535350"
        challenge_length = 16
        offset = payload_str.find(ntlmssp_signature)
        payload_str = payload_str[offset:]
        payload_bytes = bytes.fromhex(payload_str)

        data['type'] = find_int(payload_bytes, 8, 4)
        match data['type']:
            case 2:
                data['challenge'] = payload_str[48: 48 + challenge_length]
                return 'challenge', data
            case 3:
                data['lm_response'] = find_word(payload_bytes, 12,2,16,4)
                data['nt_response'] = find_word(payload_bytes, 20, 2, 24, 4)
                data['domain'] = decode_word(payload_bytes, 28,2,32,4)
                data['username'] = decode_word(payload_bytes, 36,2, 40, 4)
                data['workstation'] = decode_word(payload_bytes, 44, 2, 48,  4)
                if len(data['nt_response']) == 0:
                    return None, None
                version = 'nt_response_v1'
                if len(data['nt_response'])>48:
                    version = 'nt_response_v2'
                return version, data
            case _:
                return None, None
    except Exception as e:
        return None, None
    

