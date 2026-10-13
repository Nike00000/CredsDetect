from dataclasses import dataclass
from dto.base_data import BaseData
from dto.enums import AuthenticationProtocolEnum
from dto.enums import NTLMResponseEnum
from abc import ABC, abstractmethod

@dataclass
class NetNTLMData(BaseData):
    """Общий DTO для всех NTLM-сообщений."""
    authentication_protocol: str = AuthenticationProtocolEnum.NETNTLM.value
    name: str = 'netntlm'
    username: str = None
    domain: str = None

    @property
    def protocol(self) -> str:
        return AuthenticationProtocolEnum.NETNTLM.value

    @property
    def key(self) -> str:
        return f"{self.protocol}_{self.dst_ip}_{self.username}_{self.domain}"

    @property
    def is_user(self) -> bool:
        return True

@dataclass
class ChallengeNetNTLM(NetNTLMData):
    name = 'challenge'
    challenge: str = ''

    @property
    def key(self) -> str:
        key = self.session_id + self.challenge
        return key.lower()

    @property
    def data(self) -> str:
        return self.challenge

    @property
    def is_user(self) -> bool:
        return False

@dataclass
class ResponseNetNTLM(NetNTLMData, ABC):

    name: str = 'response'
    domain: str = ''
    username: str = ''
    lm_response: str = ''
    server_challenge: str = None

    @property
    @abstractmethod
    def version(self) -> NTLMResponseEnum:
        ...

    @property
    @abstractmethod
    def data(self) -> str:
        ...

    @property
    def has_challenge(self) -> bool:
        return self.server_challenge is not None
    
    @property
    def is_user(self) -> bool:
        return '$' not in self.username

    @property   
    def key(self) -> str:
        domain_short = self.domain.split('.')[0] if self.domain else ''
        return f"{self.username}@{domain_short}::{self.lm_response}:{self.nt_response}".lower()

@dataclass
class RespV1NetNTLM(ResponseNetNTLM):
    """NTLMv1 response (24 байта, без ESS)."""
    name: str = 'response_v1'
    nt_response: str = ''
    @property
    def version(self):
        return NTLMResponseEnum.RESPONSE_V1

    @property
    def data(self) -> str:
        if self.server_challenge:
            return f"{self.username}::{self.domain}::{self.lm_response}:{self.nt_response}:{self.server_challenge}"
        return f"{self.username}::{self.domain}::{self.lm_response}:{self.nt_response}:(unknown_server_challenge)"

@dataclass
class RespV1ESSNetNTLM(RespV1NetNTLM):
    """NTLMv1 ESS: LM response = client_challenge + 16 нулей."""
    name: str = 'response_v1_ess'
    client_challenge: str = ''
    nt_response: str = ''

    @property
    def version(self):
        return NTLMResponseEnum.RESPONSE_V1ESS

    @property
    def data(self) -> str:
        if self.server_challenge:
            return f"{self.username}::{self.domain}:{self.lm_response}:{self.nt_response}:{self.server_challenge}"
        return f"{self.username}::{self.domain}:{self.lm_response}:{self.nt_response}:(unknown_server_challenge)"

@dataclass
class RespV2NetNTLM(RespV1NetNTLM):
    """NTLMv1 ESS: LM response = client_challenge + 16 нулей."""
    name: str = 'response_v1_ess'
    client_challenge: str = ''
    ntproofstr: str = ''
    blob: str = ''
    
    @property
    def version(self):
        return NTLMResponseEnum.RESPONSE_V2

    @property
    def data(self) -> str:
        if self.server_challenge:
            return f"{self.username}::{self.domain}:{self.server_challenge}:{self.ntproofstr}:{self.blob}"
        return f"{self.username}::{self.domain}:(unknown_server_challenge):{self.ntproofstr}:{self.blob}"