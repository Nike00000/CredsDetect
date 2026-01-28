from enum import Enum

class BasicTypeEnum(Enum):
    USERNAME = 'username'
    PASSWORD = 'password'

class KerberosEtypeEnum(Enum):
    e17 = 17
    e18 = 18
    e23 = 23

class NTLMResponseEnum(Enum):
    RESPONSE_V1 = 'v1'
    RESPONSE_V2 = 'v2'

class ProtocolEnum(Enum):
    TCP = 'TCP'
    FTP = 'FTP'
    HTTP_ProxyAuthenticate = 'HTTP.ProxyAuthenticate'
    HTTP_ProxyAuthorization = 'HTTP.ProxyAuthorization'
    HTTP_Authorization = 'HTTP.Authorization'
    IMAP = 'IMAP'
    POP = 'POP'
    SMTP = 'SMTP'

class UserPassProtocolEnum(Enum):
    FTP = 'FTP'
    HTTP_ProxyAuthenticate = 'HTTP.ProxyAuthenticate'
    HTTP_ProxyAuthorization = 'HTTP.ProxyAuthorization'
    HTTP_Authorization = 'HTTP.Authorization'
    IMAP = 'IMAP'
    POP = 'POP'
    SMTP = 'SMTP'

class AuthenticationProtocolEnum(Enum):
    CLEARTEXT = 'ClearText'
    KERBEROS = 'Kerberos'
    NETNTLM = 'NetNTLM'

class HTTPTypeEnum(Enum):
    BASIC = 'basic'
    NTLM = 'ntlm'
