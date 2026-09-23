from dto.enums import BasicTypeEnum, UserPassProtocolEnum

class FTPParser:

    @staticmethod
    def get_command(packet) -> BasicTypeEnum:
        command = (
            packet.get('layers', {})
                  .get('ftp', {})
                  .get('ftp_ftp_request_command')
        )
        if command:
            command = command.lower()
            if command == 'user':
                return BasicTypeEnum.USERNAME
            if command == 'pass':
                return BasicTypeEnum.PASSWORD
        return None

    @staticmethod
    def get_arg(packet) -> str | None:
        return (
            packet.get('layers', {})
                  .get('ftp', {})
                  .get('ftp_ftp_request_arg')
        )

    @classmethod
    def try_parse(cls, packet):
        try:
            command = cls.get_command(packet=packet)
            if command is None:
                return None
            arg = cls.get_arg(packet=packet)

            if command == BasicTypeEnum.USERNAME and arg:
                return (UserPassProtocolEnum.FTP, arg, None)

            if command == BasicTypeEnum.PASSWORD and arg:
                return (UserPassProtocolEnum.FTP, None, arg)

            return None
        except Exception as e:
            return None