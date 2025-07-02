from parsers.tcp_parser import *

def ftp_parse(packet):
    try:
        creds = tcp_parse(packet)
        ftp_layer = packet.ftp
        if ftp_layer._all_fields['ftp.request'] == '1':
            for key_ftp in ftp_layer._all_fields.keys():
                if isinstance(ftp_layer._all_fields[key_ftp],dict):
                    creds['user'] = ftp_layer._all_fields[key_ftp]['ftp.request.command']
                    creds['pass'] = ftp_layer._all_fields[key_ftp]['ftp.request.arg']
                    return creds
        return None
    except:
        return None