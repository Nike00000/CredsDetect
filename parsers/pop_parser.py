from dto.enums import BasicTypeEnum

class POPParser:

    @staticmethod
    def get_command(packet) -> BasicTypeEnum:
        command = packet['layers']['pop']['pop_pop_request_command'].lower()
        if command == 'user':
            return BasicTypeEnum.USERNAME
        elif command == 'pass':
            return BasicTypeEnum.PASSWORD
        raise TypeError("Unnknown command for POP protocol")
    @staticmethod
    def get_arg(packet) -> str:
        return packet['layers']['pop']['pop_pop_request_parameter']