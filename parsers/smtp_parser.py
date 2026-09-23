import base64
from dto.enums import UserPassProtocolEnum

class SMTPParser:

    @staticmethod
    def decode_base64_string(base64_string: str) -> str | None:
        if base64_string is None:
            return None
        try:
            base64_bytes = base64_string.encode("utf-8")
            sample_string_bytes = base64.b64decode(base64_bytes, validate=True)
            return sample_string_bytes.decode("utf-8")
        except Exception as e:
            return None

    @staticmethod
    def get_username(packet) -> str | None:
        encoded = (
            packet.get('layers', {})
                  .get('smtp', {})
                  .get('smtp_smtp_auth_username')
        )
        return SMTPParser.decode_base64_string(encoded)

    @staticmethod
    def get_password(packet) -> str | None:
        encoded = (
            packet.get('layers', {})
                  .get('smtp', {})
                  .get('smtp_smtp_auth_password')
        )
        return SMTPParser.decode_base64_string(encoded)

    @classmethod
    def try_parse(cls, packet):
        try:
            username = cls.get_username(packet=packet)
            password = cls.get_password(packet=packet)

            if username or password:
                return (UserPassProtocolEnum.SMTP, username, password)
            return None
        except Exception as e:
            raise TypeError(
                f'No simple data for SMTP protocol, exception: {e}'
            ) from e