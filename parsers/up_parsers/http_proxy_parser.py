import base64
from typing import Optional, Dict
from parsers.base_parser import BaseParser
from parsers.up_parsers.up_parser import UPData
from dto.enums import UserPassProtocolEnum

class HTTPProxyAuthParser(BaseParser):
    SEP: str = '\x1f'
    Y_FIELDS: str = ['http.proxy_authorization',
                     'http.proxy_authenticate']
    E_FIELDS: list[str] = [
        'http.proxy_authorization',
    ]

    @classmethod
    def parse(cls, fields: Dict[str, str]) -> Optional[UPData]:
        raw = fields.get('http.proxy_authorization') or None
        up_protocol = UserPassProtocolEnum.HTTP_ProxyAuthorization
        if not raw:
            raw = fields.get('http.proxy_authenticate') or None
            up_protocol = UserPassProtocolEnum.HTTP_ProxyAuthenticate
            if not raw:
                return None

        username = None
        password = None

        if raw.startswith('Basic '):
            try:
                decoded = base64.b64decode(raw[6:]).decode('utf-8', errors='replace')
                if ':' in decoded:
                    username, password = decoded.split(':', 1)
            except Exception:
                pass

        if not username and not password:
            return None

        base = BaseParser.get_base_dict(fields=fields)
        
        return UPData(
            **base,
            username=username,
            password=password,
            up_protocol=up_protocol
        )