from dto.enums import UserPassProtocolEnum, HTTPTypeEnum
import base64
    
class HTTPParser:

    # --- извлечение заголовков ---

    @staticmethod
    def _dig(packet, key):
        return packet.get('layers', {}).get('http', {}).get(key)

    @classmethod
    def extract_proxy_authenticate(cls, packet) -> str | None:
        return cls._dig(packet, 'http_http_proxy_authenticate')

    @classmethod
    def extract_proxy_authorization(cls, packet) -> str | None:
        return cls._dig(packet, 'http_http_proxy_authorization')

    @classmethod
    def extract_http_authorization(cls, packet) -> str | None:
        return cls._dig(packet, 'http_http_authorization')

    # --- разбор значения Authorization ---

    @staticmethod
    def get_type_auth(authorization: str) -> HTTPTypeEnum:
        parts = authorization.split(maxsplit=1)
        if not parts:
            raise TypeError('Empty Authorization header')
        auth_type = parts[0].lower()
        if auth_type == 'basic':
            return HTTPTypeEnum.BASIC
        if auth_type == 'ntlm':
            return HTTPTypeEnum.NTLM
        raise TypeError(f'Unknown HTTP auth type: {auth_type!r}')
        
    @staticmethod
    def get_ntlm(authorization: str) -> str:
        parts = authorization.split(maxsplit=1)
        if len(parts) < 2:
            raise TypeError('NTLM token is missing')
        try:
            return base64.b64decode(parts[1], validate=True).hex()
        except Exception as e:
            raise TypeError(f'Bad NTLM base64: {e}') from e

    @staticmethod
    def _decode_basic(authorization: str) -> tuple[str, str]:
        parts = authorization.split(maxsplit=1)
        if len(parts) < 2:
            raise TypeError('Basic credentials are missing')
        try:
            decoded = base64.b64decode(parts[1], validate=True).decode('utf-8')
        except Exception as e:
            raise TypeError(f'Bad Basic base64: {e}') from e
        user, _, password = decoded.partition(':')
        return user, password

    @classmethod
    def get_basic_auth_user(cls, authorization: str) -> str:
        return cls._decode_basic(authorization)[0]

    @classmethod
    def get_basic_auth_pass(cls, authorization: str) -> str:
        return cls._decode_basic(authorization)[1]

    @classmethod
    def try_parse(cls, packet):
        candidates = (
            (cls.extract_proxy_authenticate, UserPassProtocolEnum.HTTP_ProxyAuthenticate),
            (cls.extract_proxy_authorization, UserPassProtocolEnum.HTTP_ProxyAuthorization),
            (cls.extract_http_authorization,  UserPassProtocolEnum.HTTP_Authorization),
        )

        for extractor, proto in candidates:
            authorization = extractor(packet=packet)
            if authorization is None:
                continue

            try:
                auth_type = cls.get_type_auth(authorization=authorization)
            except TypeError:
                return None

            if auth_type == HTTPTypeEnum.BASIC:
                user, password = cls._decode_basic(authorization)
                return (proto, user, password)

            if auth_type == HTTPTypeEnum.NTLM:
                # NTLM — не пара user/pass, тут возвращать нечего в формате userpass
                return None

            return None

        return None