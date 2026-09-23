from dto.enums import BasicTypeEnum, UserPassProtocolEnum

class POPParser:

    @staticmethod
    def get_command(packet) -> BasicTypeEnum:
        command = (
            packet.get('layers', {})
                  .get('pop', {})
                  .get('pop_pop_request_command')
        )
        if command is None:
            raise TypeError('No POP command in packet')

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
                  .get('pop', {})
                  .get('pop_pop_request_parameter')
        )

    @classmethod
    def try_parse(cls, packet):
        try:
            command = cls.get_command(packet=packet)
            if command:
                arg = cls.get_arg(packet=packet)
                if command == BasicTypeEnum.USERNAME and arg:
                    return (UserPassProtocolEnum.POP, arg, None)
                if command == BasicTypeEnum.PASSWORD and arg:
                    return (UserPassProtocolEnum.POP, None, arg)
            return None
        except Exception as e:
            raise TypeError(
                f'No simple data for POP protocol, exception: {e}'
            ) from e