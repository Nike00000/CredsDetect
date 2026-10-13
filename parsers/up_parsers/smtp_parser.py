import base64
from typing import Dict, Any, Optional
from parsers.up_parsers.up_parser import UPParser
from dto.enums import UserPassProtocolEnum

class SMTPParser(UPParser):

    Y_FIELDS = ['smtp.auth.username',
                'smtp.auth.password']
    E_FIELDS = ['smtp.auth.username',
                'smtp.auth.password']

    @classmethod
    def decode_base64_string(cls, base64_string: str) -> str | None:
        if base64_string is None:
            return None
        try:
            base64_bytes = base64_string.encode("utf-8")
            sample_string_bytes = base64.b64decode(base64_bytes, validate=True)
            return sample_string_bytes.decode("utf-8")
        except Exception as e:
            return None

    @classmethod
    def get_username(cls, fields: Dict[str, Any]) -> Optional[str]:
        username = fields.get('smtp.auth.username') or None
        if username :
            return cls.decode_base64_string(username)
        return None

    @classmethod
    def get_password(cls, fields: Dict[str, Any]) -> Optional[str]:
        password = fields.get('smtp.auth.password') or None
        if password:
            return cls.decode_base64_string(password)
        return None

    @classmethod
    def get_protocol(cls) -> UserPassProtocolEnum:
        return UserPassProtocolEnum.SMTP