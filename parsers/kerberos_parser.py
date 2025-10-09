def kerberos_packet(packet):
    try:
        if not 'kerberos' in packet:
            return None, None, None, None
        kerberos_layer = packet.kerberos
        if 'as_req_element' in kerberos_layer.field_names:
            data_type, data = asreq_packet(kerberos_layer.as_req_element)
        elif 'as_rep_element' in kerberos_layer.field_names:
            data_type, data = asrep_packet(kerberos_layer.as_rep_element)
        elif 'tgs_rep_element' in kerberos_layer.field_names:
            data_type, data = tgsrep_packet(kerberos_layer.tgs_rep_element)
        else:
            return None, None, None, None
        return 'TCP', 'Kerberos', data_type, data
    except:
        return None, None, None, None

def asreq_packet(as_req_layer):
    try:
        data = dict()
        data['cname'] = as_req_layer.req_body_element.cname_element.cname_string_tree.CNameString
        if type(data['cname']) == list:
            data['cname'] = '/'.join(data['cname'])
        data['realm'] = as_req_layer.req_body_element.realm
        pa_data_count = int(as_req_layer.padata)
        for index in range(pa_data_count):
            pa_data_element = as_req_layer.padata_tree.PA_DATA_element[index]
            pa_data_value_tree = pa_data_element.padata_type_tree.padata_value_tree
            data['etype'] = int(pa_data_value_tree.etype)
            data['cipher'] = str(pa_data_value_tree.cipher).replace(':', '')
            return f'asreq_{data['etype']}', data
        return None, None
    except:
        return None, None

def asrep_packet(as_rep_layer):
    try:
        data = dict()
        data['cname'] = as_rep_layer.cname_element.cname_string_tree.CNameString
        data['realm'] = as_rep_layer.crealm
        data['etype'] = int(as_rep_layer.enc_part_element.etype)
        data['cipher'] = str(as_rep_layer.enc_part_element.cipher).replace(':', '')
        return f'asrep_{data['etype']}', data
    except:
        return None, None

def tgsrep_packet(tgs_rep_layer):
    try:
        data = dict()
        data['cname'] = tgs_rep_layer.cname_element.cname_string_tree.CNameString
        sname = []
        for index in range(int(tgs_rep_layer.ticket_element.sname_element.sname_string)):
            sname.append(tgs_rep_layer.ticket_element.sname_element.sname_string_tree.SNameString[index])
        data['sname'] = '/'.join(sname)
        data['realm'] = tgs_rep_layer.crealm
        data['etype'] = int(tgs_rep_layer.ticket_element.enc_part_element.etype)
        data['cipher'] = str(tgs_rep_layer.ticket_element.enc_part_element.cipher).replace(':', '')
        return f'tgsrep_{data['etype']}', data
    except:
        return None, None