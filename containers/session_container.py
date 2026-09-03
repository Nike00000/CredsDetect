from dataclasses import dataclass, field
from typing import overload, Union, List, Dict, TypeVar, Generic
from dto.user_pass_data import UserPassData
from containers.unique_container import UniqueContainer
from dto.enums import UserPassProtocolEnum
from dto.base_data import BaseData

T = TypeVar('T', bound='BaseData')

@dataclass
class SessionContainer(Generic[T]):
    
    sessions: Dict[str, List[T]] = field(
            default_factory=dict,
            init=False
        )
    
    def append(self, data: T) -> None:
        if not self.sessions.get(data.id_session):
            self.sessions[data.id_session] = []
        self.sessions[data.id_session].append(data)
        self.sessions[data.id_session].sort(key=lambda x: x.timestamp)
