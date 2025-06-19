

def asreq_packet(kerberos_layer):
    try:
        as_req = {'cname': "",
                  'realm': "",
                  'etype': 0,
                  'cipher': ""}
        # Парсим как AS-REQ
        as_req_layer = kerberos_layer.as_req_element
        as_req['cname'] = as_req_layer.req_body_element.cname_element.cname_string_tree.CNameString
        as_req['realm'] = as_req_layer.req_body_element.realm
        padata_count = int(as_req_layer.padata)
        for index in range(padata_count):
            pa_data_element = as_req_layer.padata_tree.PA_DATA_element[index]
            if pa_data_element.padata_type_tree.padata_value is None:
                return None
            else:
                as_req['etype'] = int(pa_data_element.padata_type_tree.padata_value_tree.etype)
                as_req['cipher'] = str(pa_data_element.padata_type_tree.padata_value_tree.cipher).replace(':', '')
                return as_req
    except:
        pass

def asrep_packet(kerberos_layer):
    try:
        # Парсим как AS-REP
        as_rep_layer = kerberos_layer.as_rep_element

        as_rep = {'cname': "",
                  'realm': "",
                  'etype': 0,
                  'cipher': ""}

        as_rep['cname'] = as_rep_layer.cname_element.cname_string_tree.CNameString
        as_rep['realm'] = as_rep_layer.crealm
        as_rep['etype'] = int(as_rep_layer.ticket_element.enc_part_element.etype)
        as_rep['cipher'] = str(as_rep_layer.ticket_element.enc_part_element.cipher).replace(':', '')

        return as_rep
    except:
        pass

def tgsrep_packet(kerberos_layer):
    try:
        # Парсим как TGS-REP
        tgs_rep = {'cname': "",
                   'sname': "",
                   'realm': "",
                   'etype': 0,
                   'cipher': ""}
        tgs_rep_layer = kerberos_layer.tgs_rep_element
        tgs_rep['cname'] = tgs_rep_layer.cname_element.cname_string_tree.CNameString
        sname = []
        for index in range(int(tgs_rep_layer.ticket_element.sname_element.sname_string)):
            sname.append(tgs_rep_layer.ticket_element.sname_element.sname_string_tree.SNameString[index])
        tgs_rep['sname'] = '/'.join(sname)
        tgs_rep['realm'] = tgs_rep_layer.crealm
        tgs_rep['etype'] = int(tgs_rep_layer.ticket_element.enc_part_element.etype)
        tgs_rep['cipher'] = str(tgs_rep_layer.ticket_element.enc_part_element.cipher).replace(':', '')
        return tgs_rep
    except:
        pass