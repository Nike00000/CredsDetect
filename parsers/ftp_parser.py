def ftp_parse(packet):
    try:
        data = dict()
        ftp_layer = packet['ftp']
        if ftp_layer['ftp_ftp_request']:
            command = ftp_layer['ftp_ftp_request_command'].lower()
            data[command] = ftp_layer['ftp_ftp_request_arg']
            return 'FTP', 'ClearText', command, data
        return None, None, None, None
    except:
        return None, None, None, None