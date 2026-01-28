from dto.enums import BasicTypeEnum

class FTPParser:

    @staticmethod
    def get_command(packet) -> BasicTypeEnum:
        command = packet['layers']['ftp']['ftp_ftp_request_command'].lower()
        if command == 'user':
            return BasicTypeEnum.USERNAME
        elif command == 'pass':
            return BasicTypeEnum.PASSWORD
        raise TypeError("Unnknown command for FTP protocol")
    
    @staticmethod
    def get_arg(packet) -> str:
        return packet['layers']['ftp']['ftp_ftp_request_arg']