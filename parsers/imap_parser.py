from dto.enums import BasicTypeEnum

class IMAPParser:

    @staticmethod
    def get_username(packet) -> BasicTypeEnum:
        username = packet['layers']['imap']['imap_imap_request_username']
        return username
    
    @staticmethod
    def get_password(packet) -> BasicTypeEnum:
        password = packet['layers']['imap']['imap_imap_request_password']
        return password