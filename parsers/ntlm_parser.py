from parsers.tcp_parser import tcp_parse
import base64

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

def ntlm_parse(packet):
    try:
        ntlm_cred = tcp_parse(packet)
        ntlmssp_signature = "4e544c4d535350"
        challenge_length = 16

        payload = packet.tcp.payload

        payload_str = str(payload).replace(':','')
        offset = payload_str.find(ntlmssp_signature)

        if offset < 0:
            #Try proxy HTTP
            try:
                proxy_str = str(packet.http.proxy_authorization)
            except:
                proxy_str = str(packet.http.proxy_authenticate)
            payload_base64 = proxy_str.split(' ')[1]
            payload_str= base64.b64decode(payload_base64).hex()
            offset = payload_str.find(ntlmssp_signature)
            if offset < 0:
                return None

        payload_str = payload_str[offset:]

        payload_bytes = bytes.fromhex(payload_str)

        ntlm_cred['type'] = find_int(payload_bytes, 8, 4)
        match ntlm_cred['type']:
            case 1:
                return None
            case 2:
                ntlm_cred['challenge'] = payload_str[48: 48 + challenge_length]
            case 3:
                ntlm_cred['lm_response'] = find_word(payload_bytes, 12,2,16,4)
                ntlm_cred['nt_response'] = find_word(payload_bytes, 20, 2, 24, 4)
                ntlm_cred['domain'] = decode_word(payload_bytes, 28,2,32,4)
                ntlm_cred['username'] = decode_word(payload_bytes, 36,2, 40, 4)
                ntlm_cred['workstation'] = decode_word(payload_bytes, 44, 2, 48,  4)
        return ntlm_cred
    except Exception as e:
        return None
    

