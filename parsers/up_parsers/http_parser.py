import base64
from typing import ClassVar, Optional, Dict
from parsers.base_parser import BaseParser
from parsers.up_parsers.up_parser import UPData
from dto.enums import UserPassProtocolEnum

class HTTPAuthParser(BaseParser):
    SEP: ClassVar[str] = '\x1f'
    Y_FIELDS: ClassVar[str] = ['http.authbasic',
                                'http.authorization']
    E_FIELDS: ClassVar[list[str]] = [
        'http.authbasic',
        'http.authorization',
    ]

    @classmethod
    def parse(cls, fields: Dict[str, str]) -> Optional[UPData]:

        username = None
        password = None
        raw_auth = None

        # 1. http.authbasic — Wireshark уже декодировал
        authbasic = fields.get('http.authbasic') or None
        if authbasic and ':' in authbasic:
            username, password = authbasic.split(':', 1)
            username = username or None
            password = password or None

        # 2. http.authorization — сырой заголовок, декодируем сами
        elif (auth := fields.get('http.authorization')):
            raw_auth = auth
            if auth.startswith('Basic '):
                try:
                    decoded = base64.b64decode(auth[6:]).decode('utf-8', errors='replace')
                    if ':' in decoded:
                        username, password = decoded.split(':', 1)
                        username = username or None
                        password = password or None
                except Exception:
                    pass

        if not username and not password:
            return None

        base = BaseParser.get_base_dict(fields=fields)

        return UPData(
            **base,
            username=username,
            password=password,
            up_protocol=UserPassProtocolEnum.HTTP_Authorization
        )