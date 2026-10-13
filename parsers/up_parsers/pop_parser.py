from typing import Dict, Any, Optional

from dto.enums import UserPassProtocolEnum
from parsers.up_parsers.up_parser import UPParser

class POPParser(UPParser):
    Y_FIELDS = ['pop.request.command == "USER"',
                'pop.request.command == "PASS"']
    E_FIELDS = ['pop.request.command',
                'pop.request.parameter']

    @classmethod
    def get_username(cls, fields: Dict[str, Any]) -> Optional[str]:
        command = fields.get('pop.request.command')
        arg = fields.get('pop.request.parameter')
        if command is None or arg is None:
            return None
        if command.upper() == "USER":
            return arg
        return None

    @classmethod
    def get_password(cls, fields: Dict[str, Any]) -> Optional[str]:
        command = fields.get('pop.request.command')
        arg = fields.get('pop.request.parameter')
        if command is None or arg is None:
            return None
        if command.upper() == "PASS":
            return arg
        return None

    @classmethod
    def get_protocol(cls) -> UserPassProtocolEnum:
        return UserPassProtocolEnum.POP