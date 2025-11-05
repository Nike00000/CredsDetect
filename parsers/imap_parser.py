def imap_packet(packet):
    try:
        data = dict()
        imap_line = packet['imap']['imap_imap_line']
        imap_is_request = packet['imap']['imap_imap_isrequest']
        line = imap_line.replace('\n','').replace('\r','')
        if 'LOGIN' in line and imap_is_request:
            data['user'] = line.split(' ')[2][1:-1]
            data['pass'] = line.split(' ')[3][1:-1]
            return 'IMAP', 'ClearText', 'user:pass', data
        return None, None, None, None
    except:
        return None, None, None, None