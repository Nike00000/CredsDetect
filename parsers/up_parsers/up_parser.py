from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

from dto.enums import UserPassProtocolEnum
from dto.user_pass_data import UPData
from parsers.base_parser import BaseParser


class UPParser(ABC):

    @classmethod
    @abstractmethod
    def get_username(cls, fields: Dict[str, Any]) -> Optional[str]:
        ...

    @classmethod
    @abstractmethod
    def get_password(cls, fields: Dict[str, Any]) -> Optional[str]:
        ...

    @classmethod
    def parse(cls, fields: Dict[str, Any]) -> Optional[UPData]:
        username = cls.get_username(fields)
        password = cls.get_password(fields)

        if not username and not password:
            return None

        base = BaseParser.get_base_dict(fields=fields)

        return UPData(
            **base,
            username=username,
            password=password,
            up_protocol=cls.get_protocol(),
        )

    @classmethod
    @abstractmethod
    def get_protocol(cls) -> UserPassProtocolEnum:
        ...
