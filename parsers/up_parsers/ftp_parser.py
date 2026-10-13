from typing import Dict, Any, Optional

from dto.enums import UserPassProtocolEnum
from parsers.up_parsers.up_parser import UPParser

class FTPParser(UPParser):
    Y_FIELDS = ['ftp.request.command == "USER"',
                'ftp.request.command == "PASS"']
    E_FIELDS = ['ftp.request.command',
                'ftp.request.arg']

    @classmethod
    def get_username(cls, fields: Dict[str, Any]) -> Optional[str]:
        command = fields.get('ftp.request.command')
        arg = fields.get('ftp.request.arg')
        if command is None or arg is None:
            return None
        if command.upper() == "USER":
            return arg
        return None

    @classmethod
    def get_password(cls, fields: Dict[str, Any]) -> Optional[str]:
        command = fields.get('ftp.request.command')
        arg = fields.get('ftp.request.arg')
        if command is None or arg is None:
            return None
        if command.upper() == "PASS":
            return arg
        return None

    @classmethod
    def get_protocol(cls) -> UserPassProtocolEnum:
        return UserPassProtocolEnum.FTP