from dto.enums import BasicTypeEnum, UserPassProtocolEnum

class LDAPParser:

    @staticmethod
    def get_username(packet) -> str | None:
        return (
            packet.get('layers', {})
                  .get('ldap', {})
                  .get('ldap_ldap_name')
        )

    @staticmethod
    def get_password(packet) -> str | None:
        return (
            packet.get('layers', {})
                  .get('ldap', {})
                  .get('ldap_ldap_simple')
        )

    @classmethod
    def try_parse(cls, packet):
        try:
            username = cls.get_username(packet=packet)
            password = cls.get_password(packet=packet)

            if username or password:
                return (UserPassProtocolEnum.LDAP, username, password)

            return None
        except Exception as e:
            raise TypeError(
                f'No simple data for LDAP protocol, exception: {e}'
            ) from e