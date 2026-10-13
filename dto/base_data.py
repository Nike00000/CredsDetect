from abc import ABC, abstractmethod
from dataclasses import dataclass

@dataclass
class BaseData(ABC):
    filename: str = ''
    timestamp: int = 0
    number: int = 0
    src_mac: str = ''
    dst_mac: str = ''
    src_ip: str = ''
    dst_ip: str = ''
    src_port: str = ''
    dst_port: str = ''
    
    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @property
    @abstractmethod
    def protocol(self) -> str:
        ...

    @property
    @abstractmethod
    def authentication_protocol(self) -> str:
        ...

    @property
    @abstractmethod
    def key(self) -> str:
        ...

    @property
    @abstractmethod
    def data(self) -> str:
        ...
    
    @property
    @abstractmethod
    def is_user(self) -> bool:
        ...

    @property
    def session_id(self) -> str:
        return f"{self.socket_session}:{self.protocol}"

    @property
    def socket_session(self) -> str:
        src_socket = f"{self.src_ip}:{self.src_port}"
        dst_socket = f"{self.dst_ip}:{self.dst_port}"
        socket_session1 = min(src_socket, dst_socket)
        socket_session2 = max(src_socket, dst_socket)
        return '-'.join([socket_session1, socket_session2])
    