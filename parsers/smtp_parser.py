import base64

from dto.enums import BasicTypeEnum

class SMTPParser:
    @staticmethod
    def get_username(packet) -> BasicTypeEnum:
        username_encode = packet['layers']['smtp']['smtp_smtp_auth_username']
        return SMTPParser.decode_base64_string(username_encode)
    
    @staticmethod
    def get_password(packet) -> BasicTypeEnum:
        password_encode = packet['layers']['smtp']['smtp_smtp_auth_password']
        return SMTPParser.decode_base64_string(password_encode)
    
    @staticmethod
    def decode_base64_string(base64_string):
        base64_bytes = base64_string.encode("utf-8")
        sample_string_bytes = base64.b64decode(base64_bytes)
        sample_string = sample_string_bytes.decode("utf-8")
        return sample_string