from dataclasses import dataclass
from dto.base_data import BaseData, AuthenticationProtocolEnum
from dto.enums import NTLMResponseEnum, ProtocolEnum
from parsers.ntlm_parser import NTLMParser
from parsers.http_parser import HTTPParser, HTTPTypeEnum



@dataclass
class NetNTLMExtractor(BaseData):
    _payload_bytes: bytes = None
    _protocol: str = ''

    def __init__(self, packet, filename):
        super().__init__(packet=packet, filename=filename)
        try:
            self._payload_bytes = NTLMParser.extract_payload_bytes(packet=packet)
            self._protocol = ProtocolEnum.TCP.value
        except:
            pass
        if  self._payload_bytes != None:
            return
        authorization = None
        try:
            authorization = HTTPParser.extract_proxy_authenticate(packet=packet)
            self._protocol = ProtocolEnum.HTTP_ProxyAuthenticate.value
        except:
            pass
        try:
            authorization = HTTPParser.extract_proxy_authorization(packet=packet)
            self._protocol = ProtocolEnum.HTTP_ProxyAuthorization.value
        except:
            pass
        try:
            authorization = HTTPParser.extract_http_authorization(packet=packet)
            self._protocol = ProtocolEnum.HTTP_Authorization.value
        except:
            pass
        if authorization == None:
            raise TypeError("NTLM data don't found in packet")
        autorization_type = HTTPParser.get_type_auth(authorization=authorization)
        if autorization_type == HTTPTypeEnum.NTLM:
            self._payload_bytes = HTTPParser.get_ntlm(authorization=authorization)
        else:
            raise TypeError("Unsupported type http authorization")

@dataclass
class ChallengeNetNTLM(NetNTLMExtractor):
    authentication_protocol: AuthenticationProtocolEnum = AuthenticationProtocolEnum.NETNTLM.value
    challenge: str = ''
    name = 'challenge'

    def __init__(self, packet, filename):
        super().__init__(packet=packet, filename=filename)

        type_ntlm = NTLMParser.get_message_type(payload_bytes=self._payload_bytes)
        if type_ntlm == 2:
            self.challenge = NTLMParser.get_challenge(payload_bytes=self._payload_bytes)
        else:
            raise ValueError("The message type is not as expected for the challenge")
        
    def protocol(self) -> str:
        return self._protocol
    
    def key(self) -> str:
        key = self.session_id + self.type
        return key.lower()
    
    def data(self) -> str:
        return self.challenge
    
    def is_user(self) -> bool:
        return False


@dataclass
class ResponseNetNTLM(NetNTLMExtractor):
    domain: str = ''
    username: str = ''
    workstation: str = ''
    authentication_protocol: AuthenticationProtocolEnum = AuthenticationProtocolEnum.NETNTLM.value
    name: str = 'response'
    lm_response: str = ''
    nt_response: str = ''
    _protocol: ProtocolEnum = None

    def __init__(self, packet, filename):
        super().__init__(packet=packet, filename=filename)

        type_ntlm = NTLMParser.get_message_type(payload_bytes=self._payload_bytes)
        
        if type_ntlm == 3:
            self.domain = NTLMParser.get_domain(payload_bytes=self._payload_bytes)
            self.username = NTLMParser.get_username(payload_bytes=self._payload_bytes)
            self.workstation = NTLMParser.get_workstation(payload_bytes=self._payload_bytes)
            self.lm_response = NTLMParser.get_lm_response(payload_bytes=self._payload_bytes)
            self.nt_response = NTLMParser.get_nt_response(payload_bytes=self._payload_bytes)
        else:
            raise ValueError("The message type is not as expected for the response")
            
    def version(self) -> NTLMResponseEnum:
        if len(self.nt_response) > 48:
            return NTLMResponseEnum.RESPONSE_V2
        else:
            return NTLMResponseEnum.RESPONSE_V1
        
    def protocol(self) -> str:
        return self._protocol
    
    def is_user(self) -> bool:
        return '$' not in self.username
    
    def key(self) -> str:
        key = f"{self.username}@{self.domain.split('.')[0]}{self.version().value}"
        return key.lower()
    
    def data(self) -> str:
        text = ''
        if self.version() == NTLMResponseEnum.RESPONSE_V1:
            text = f"{self.username}@{self.domain}::{self.nt_response}:{self.nt_response}"
        elif self.version() == NTLMResponseEnum.RESPONSE_V2:
            text = f"{self.username}::{self.domain}:{self.nt_response[:32]}:{self.nt_response[32:]}"
        return text
    

@dataclass
class HashNetNTLM(BaseData):
    challenge: ChallengeNetNTLM = None
    response: ResponseNetNTLM = None
    authentication_protocol: AuthenticationProtocolEnum = AuthenticationProtocolEnum.NETNTLM.value
    name: str = 'hash'
    
    def __init__(self, challenge: ChallengeNetNTLM, response: ResponseNetNTLM):
        super().__init__(packet=response._packet, filename=response.filename)
        self.challenge = challenge
        self.response = response

    def version(self) -> NTLMResponseEnum:
        return self.response.version()
        
    def protocol(self) -> str:
        return self.response._protocol.value
    
    def is_user(self) -> bool:
        return self.response.is_user()
    
    def key(self) -> str:
        key = f"{self.response.username}@{self.response.domain.split('.')[0]}{self.response.version().value}"
        return key.lower()
    
    def data(self) -> str:
        text = ""
        version = self.version()
        if version == NTLMResponseEnum.RESPONSE_V1:
            text_username = f"{self.response.username}@{self.response.domain}"
            text = f"{text_username}:{self.response.lm_response}:{self.response.nt_response}:{self.challenge.challenge}"
        elif version == NTLMResponseEnum.RESPONSE_V2:
            text_username = f"{self.response.username}::{self.response.domain}"
            text = f"{text_username}:{self.challenge.challenge}:{self.response.nt_response[:32]}:{self.response.nt_response[32:]}"
        return text