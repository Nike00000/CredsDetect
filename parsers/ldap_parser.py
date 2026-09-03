from dto.enums import BasicTypeEnum

class LDAPParser:

    @staticmethod
    def get_username(packet) -> BasicTypeEnum:
        username = packet['layers']['ldap']['ldap_ldap_name']
        return username
    
    @staticmethod
    def get_password(packet) -> BasicTypeEnum:
        password = packet['layers']['ldap']['ldap_ldap_simple']
        return password