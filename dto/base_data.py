from typing import Optional
from datetime import datetime
from dto.enums import AuthenticationProtocolEnum
from abc import ABC, abstractmethod

class BaseData(ABC):
    _packet = None
    filename: str = ''
    timestamp: int = 0
    time: Optional[datetime]
    number: int = 0
    src_mac: str = ''
    dst_mac: str = ''
    src_ip: str = ''
    dst_ip: str = ''
    session_id: str = ''
    src_port: str = ''
    dst_port: str = ''
    
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def protocol(self) -> str:
        pass

    @property
    @abstractmethod
    def authentication_protocol(self) -> str:
        pass

    @property
    @abstractmethod
    def key(self) -> str:
        pass

    @property
    @abstractmethod
    def data(self) -> str:
        pass
    
    @property
    @abstractmethod
    def is_user(self) -> bool:
        pass

    def __init__(self, packet, filename):
        unknown = 'unknown'
        self._packet = packet
        if 'layers' not in packet:
            raise ValueError('Layers not found in packet')
        self.filename = filename

        if 'timestamp' not in packet:
            raise ValueError('Timestamp not found in packet')
        self.timestamp = int(packet['timestamp'])

        layers = packet['layers']

        if not 'frame' in layers:
            raise ValueError('Frame not found in packet')
        
        self.time = datetime.fromisoformat(layers['frame']['frame_frame_time_utc'])
        self.number = layers['frame']['frame_frame_number']

        if not 'eth' in layers:
            raise ValueError('Eth not found in packet')

        self.src_mac = layers['eth'].get('eth_eth_src', unknown)
        self.dst_mac = layers['eth'].get('eth_eth_dst', unknown)

        if not 'ip' in layers:
            raise ValueError('Ip not found in packet')

        self.src_ip = layers['ip'].get('ip_ip_src', unknown)
        self.dst_ip = layers['ip'].get('ip_ip_dst', unknown)
        #Session
        session_id1 = min(self.src_ip, self.dst_ip)
        session_id2 = max(self.src_ip, self.dst_ip)

        self.session_id = '-'.join([session_id1, session_id2])

        if 'tcp' in layers:
            self.src_port = layers['tcp'].get('tcp_tcp_srcport', unknown)
            self.dst_port = layers['tcp'].get('tcp_tcp_dstport', unknown)
        if 'udp' in layers:
            self.src_port = layers['udp'].get('udp_udp_srcport', unknown)
            self.dst_port = layers['udp'].get('udp_udp_dstport', unknown)