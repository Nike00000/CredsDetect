from parsers.tcp_parser import tcp_parse

def http_auth_basic(packet):
    try:
        creds = tcp_parse(packet)
        layer = packet.http
        try:
            auth_basic = str(layer.authorization_tree.authbasic)
            creds['type'] = 'auth_basic'
        except:
            auth_basic = str(layer.proxy_authorization_tree.authbasic)
            creds['type'] = 'proxy_auth_basic'
        creds['user'] = auth_basic.split(':')[0]
        creds['pass'] = auth_basic.split(':')[1]
        creds['uri'] = str(layer.full_uri)
        return creds
    except:
        return None