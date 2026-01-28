from typing import TypeVar, Generic, List, Dict
from dataclasses import dataclass, field
from dto.base_data import BaseData

T = TypeVar('T', bound='BaseData')

@dataclass
class UniqueContainer(Generic[T]):

    all: List[T] = field(default_factory=list)
    users: List[T] = field(default_factory=list)
    _unique: Dict[str, T] = field(default_factory=dict)

    @property
    def unique(self) -> List[T]:
        return list(self._unique.values())

    def append(self, data:T) -> None:
        self.all.append(data)
        if data.is_user():
            self.users.append(data)
            self._unique[data.key()] = data
