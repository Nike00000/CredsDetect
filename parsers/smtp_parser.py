import base64

def decode_base64_string(base64_string):
    base64_bytes = base64_string.encode("utf-8")
    sample_string_bytes = base64.b64decode(base64_bytes)
    sample_string = sample_string_bytes.decode("utf-8")
    return sample_string

def smtp_packet(packet):
    try:
        data = dict()
        layer = packet.smtp
        try:
            data['user'] = decode_base64_string(layer.username)
            return 'SMTP', 'ClearText', 'user', data
        except:
            pass
        try:
            data['pass'] = decode_base64_string(layer.password)
            return 'SMTP', 'ClearText', 'pass', data
        except:
            pass
        return None, None, None, None
    except:
        return None, None, None, None