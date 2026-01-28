class KerberosParser:

    @classmethod
    def get_message_type(cls, packet) -> int:
        return int(packet['layers']['kerberos']['kerberos_kerberos_msg_type'])
    
    @classmethod
    def get_cname(cls, packet) -> str:
        name = packet['layers']['kerberos']['kerberos_kerberos_CNameString']
        if type(name) == list:
            name = '/'.join(name)
        return name
    
    @classmethod
    def get_sname(cls, packet) -> str:
        name = packet['layers']['kerberos']['kerberos_kerberos_SNameString']
        if type(name) == list:
            name = '/'.join(name)
        return name
    
    @classmethod
    def get_realm(cls, packet) -> str:
        return packet['layers']['kerberos']['kerberos_kerberos_realm']
    
    @classmethod
    def get_crealm(cls, packet) -> str:
        return packet['layers']['kerberos']['kerberos_kerberos_crealm']
    
    @classmethod
    def get_pa_enc_timestamp_cipher(cls, packet) -> str:
        return packet['layers']['kerberos']['kerberos_kerberos_pA_ENC_TIMESTAMP_cipher']
    
    @classmethod
    def get_pa_encryptedKDCREPData_cipher(cls, packet) -> str:
        return packet['layers']['kerberos']['kerberos_kerberos_encryptedKDCREPData_cipher']
    
    @classmethod
    def get_pa_encryptedTicketData_cipher(cls, packet) -> str:
        return packet['layers']['kerberos']['kerberos_kerberos_encryptedTicketData_cipher']

    @classmethod
    def get_etype(cls, packet) -> int:
        return int(packet['layers']['kerberos']['kerberos_kerberos_etype'])
    
    @classmethod
    def get_etype1(cls, packet) -> int:
        return int(packet['layers']['kerberos']['kerberos_kerberos_etype'][-1])
    
    @classmethod
    def get_etype2(cls, packet) -> int:
        return int(packet['layers']['kerberos']['kerberos_kerberos_etype'][-2])
        