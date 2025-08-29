def ftp_parse(packet):
    try:
        data = dict()
        ftp_layer = packet.ftp
        if ftp_layer._all_fields['ftp.request'] == '1':
            for key_ftp in ftp_layer._all_fields.keys():
                if isinstance(ftp_layer._all_fields[key_ftp],dict):
                    command = str(ftp_layer._all_fields[key_ftp]['ftp.request.command']).lower()
                    data[command] = ftp_layer._all_fields[key_ftp]['ftp.request.arg']
                    return 'FTP', 'ClearText', command, data
        return None, None, None, None
    except:
        return None, None, None, None