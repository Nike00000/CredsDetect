def imap_packet(packet):
    try:
        data = dict()
        imap_layer = packet.imap
        line = str(imap_layer.line).replace('\n','').replace('\r','')
        if 'LOGIN' in line and imap_layer.isrequest == '1':
            data['user'] = line.split(' ')[2][1:-1]
            data['pass'] = line.split(' ')[3][1:-1]
            return 'IMAP', 'ClearText', 'user:pass', data
        return None, None, None, None
    except:
        return None, None, None, None