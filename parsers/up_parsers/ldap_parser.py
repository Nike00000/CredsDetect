from typing import Dict, Any, Optional
from dto.enums import UserPassProtocolEnum
from parsers.up_parsers.up_parser import UPParser

class LDAPParser(UPParser):
    Y_FIELDS = ['ldap.protocolOp == 0 && ldap.simple']
    E_FIELDS = ['ldap.name',
                'ldap.simple']

    @classmethod
    def get_username(cls, fields: Dict[str, Any]) -> Optional[str]:
        return fields.get('ldap.name') or None

    @classmethod
    def get_password(cls, fields: Dict[str, Any]) -> Optional[str]:
        return fields.get('ldap.simple') or None

    @classmethod
    def get_protocol(cls) -> UserPassProtocolEnum:
        return UserPassProtocolEnum.LDAP
