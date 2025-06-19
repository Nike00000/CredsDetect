from parsers.tcp_parser import tcp_parse
import base64

def decode_base64_string(base64_string):
    base64_bytes = base64_string.encode("utf-8")
    sample_string_bytes = base64.b64decode(base64_bytes)
    sample_string = sample_string_bytes.decode("utf-8")
    return sample_string

def smtp_packet(packet):
    try:
        creds = tcp_parse(packet)
        layer = packet.smtp
        try:
            creds['username'] = decode_base64_string(layer.username)
            return creds
        except:
            pass
        try:
            creds['password'] = decode_base64_string(layer.password)
            return creds
        except:
            pass
        return None
    except:
        return None