from parsers.ntlm_parser import ntlm_parse
import base64

def http_proxy_authenticate(packet):
    try:
        authenticate = str(packet.http.proxy_authenticate)
        auth, type_data, data = http_type_auth(authenticate)
        return 'HTTP.ProxyAuthenticate', auth, type_data, data
    except:
        return None, None, None, None

def http_proxy_authorization(packet):
    try:
        authorization = str(packet.http.proxy_authorization)
        auth, type_data, data = http_type_auth(authorization)
        return 'HTTP.ProxyAuthorization', auth, type_data, data
    except:
        return None, None, None, None

def http_authorization(packet):
    try:
        authorization = packet.http.authorization
        auth, type_data, data = http_type_auth(authorization)
        return 'HTTP.Authorization', auth, type_data, data
    except:
        return None, None, None, None

def http_type_auth(authorization):
    auth_type = str(authorization).split(' ')[0]
    auth_data = str(authorization).split(' ')[1]
    auth_data_decode = base64.b64decode(auth_data).hex()
    if 'Kerberos'.lower() in auth_type.lower():
        # TODO
        return None, None, None
    elif 'Basic'.lower() in auth_type.lower():
        auth_data_decode = base64.b64decode(auth_data).decode('utf-8')
        data = http_auth_basic(auth_data_decode)
        return 'ClearText', 'user:pass', data
    elif 'NTLM'.lower() in auth_type.lower():
        data_type, data = http_auth_ntlm(auth_data_decode)
        return 'NetNTLM', data_type, data
    else:
        return None, None, None

def http_auth_basic(auth_data):
    try:
        data = dict()
        data['user'] = auth_data.split(':')[0]
        data['pass'] = auth_data.split(':')[1]

        return data
    except:
        return None

def http_auth_ntlm(auth_data):
    try:
        return ntlm_parse(auth_data)
    except:
        return None, None