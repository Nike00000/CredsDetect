def kerberos_packet(layers):
    try:
        if not 'kerberos' in layers:
            return None, None, None, None
        kerberos_layer = layers['kerberos']
        msg_type = kerberos_layer['kerberos_kerberos_msg_type']
        if msg_type == '10':
            data_type, data = asreq_packet(kerberos_layer)
        elif msg_type == '11':
            data_type, data = asrep_packet(kerberos_layer)
        elif msg_type == '13':
            data_type, data = tgsrep_packet(kerberos_layer)
        else:
            return None, None, None, None
        return 'TCP', 'Kerberos', data_type, data
    except:
        return None, None, None, None

def asreq_packet(as_req_layer):
    try:
        data = dict()
        data['cname'] = as_req_layer['kerberos_kerberos_CNameString']
        if type(data['cname']) == list:
            data['cname'] = '/'.join(data['cname'])
        data['realm'] = as_req_layer['kerberos_kerberos_realm']
        pa_data_types = as_req_layer['kerberos_kerberos_padata_type']
        index_pa_enc_timestamp = pa_data_types.index('2')
        pa_data_cipher = as_req_layer['kerberos_kerberos_pA_ENC_TIMESTAMP_cipher']
        data['cipher'] = pa_data_cipher.replace(':', '')
        data['etype'] = int(as_req_layer['kerberos_kerberos_etype'])
        return f'asreq_{data['etype']}', data
    except:
        return None, None

def asrep_packet(as_rep_layer):
    try:
        data = dict()
        data['cname'] = as_rep_layer['kerberos_kerberos_CNameString']
        data['realm'] = as_rep_layer['kerberos_kerberos_crealm']
        data['etype'] = int(as_rep_layer['kerberos_kerberos_etype'][-1])
        enc_cipher = as_rep_layer['kerberos_kerberos_encryptedKDCREPData_cipher']
        data['cipher'] = str(enc_cipher).replace(':', '')
        return f'asrep_{data['etype']}', data
    except:
        return None, None

def tgsrep_packet(tgs_rep_layer):
    try:
        data = dict()
        data['cname'] = tgs_rep_layer['kerberos_kerberos_CNameString']
        data['sname'] = tgs_rep_layer['kerberos_kerberos_SNameString']
        if type(data['sname']) == list:
            data['sname'] = '/'.join(data['sname'])

        data['realm'] = tgs_rep_layer['kerberos_kerberos_crealm']
        data['etype'] = int(tgs_rep_layer['kerberos_kerberos_etype'][-2])
        enc_cipher = tgs_rep_layer['kerberos_kerberos_encryptedTicketData_cipher']
        data['cipher'] = str(enc_cipher).replace(':', '')
        return f'tgsrep_{data['etype']}', data
    except:
        return None, None