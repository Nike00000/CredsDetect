from parsers.tcp_parser import tcp_parse

def imap_packet(packet):
    try:
        creds = tcp_parse(packet)
        imap_layer = packet.imap
        line = str(imap_layer.line).replace('\n','').replace('\r','')
        if 'LOGIN' in line and imap_layer.isrequest == '1':
            creds['username'] = line.split(' ')[2][1:-1]
            creds['password'] = line.split(' ')[3][1:-1]
            return creds
        return None
    except:
        return None