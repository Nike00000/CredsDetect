from parsers.tcp_parser import tcp_parse

def http_auth_basic_proxy(packet):
    try:
        creds = tcp_parse(packet)
        layer = packet.http
        auth_basic = str(layer.proxy_authorization_tree.authbasic)
        creds['user'] = auth_basic.split(':')[0]
        creds['pass'] = auth_basic.split(':')[1]
        creds['uri'] = str(layer.full_uri)
        return creds
    except:
        return None