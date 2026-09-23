from dto.enums import UserPassProtocolEnum

class IMAPParser:

    @staticmethod
    def get_username(packet) -> str | None:
        return (
            packet.get('layers', {})
                  .get('imap', {})
                  .get('imap_imap_request_username')
        )

    @staticmethod
    def get_password(packet) -> str | None:
        return (
            packet.get('layers', {})
                  .get('imap', {})
                  .get('imap_imap_request_password')
        )

    @classmethod
    def try_parse(cls, packet):
        try:
            username = cls.get_username(packet=packet)
            password = cls.get_password(packet=packet)

            if username is None and password is None:
                return None

            return (UserPassProtocolEnum.IMAP, username, password)
        except Exception as e:
            raise TypeError(
                f'No simple data for IMAP protocol, exception: {e}'
            ) from e