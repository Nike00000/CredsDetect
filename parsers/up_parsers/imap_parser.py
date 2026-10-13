from typing import Dict, Any, Optional
from dto.enums import UserPassProtocolEnum
from parsers.up_parsers.up_parser import UPParser

class IMAPParser(UPParser):
    Y_FIELDS = ['imap.request.command == "LOGIN"']
    E_FIELDS = ['imap.request.username',
                'imap.request.password']

    @classmethod
    def get_username(cls, fields: Dict[str, Any]) -> Optional[str]:
        return fields.get('imap.request.username') or None

    @classmethod
    def get_password(cls, fields: Dict[str, Any]) -> Optional[str]:
        return fields.get('imap.request.password') or None

    @classmethod
    def get_protocol(cls) -> UserPassProtocolEnum:
        return UserPassProtocolEnum.IMAP