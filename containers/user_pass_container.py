from dataclasses import dataclass, field
from typing import overload, Union, List, Dict
from dto.user_pass_data import UserPassData
from containers.unique_container import UniqueContainer
from dto.enums import UserPassProtocolEnum


@dataclass
class UserPassContainer:
    
    all: Dict[UserPassProtocolEnum, UniqueContainer[UserPassData]] = field(
        default_factory=dict,
        init=False
    )

    usernames: Dict[UserPassProtocolEnum, UniqueContainer[UserPassData]] = field(
        default_factory=dict,
        init=False
    )
    passwords: Dict[UserPassProtocolEnum, UniqueContainer[UserPassData]] = field(
        default_factory=dict,
        init=False
    )

    def __post_init__(self) -> None:
        self.all = {
            member: UniqueContainer[UserPassData]()
            for member in UserPassProtocolEnum
        }
        self.usernames = {
            member: UniqueContainer[UserPassData]()
            for member in UserPassProtocolEnum
        }
        self.passwords = {
            member: UniqueContainer[UserPassData]()
            for member in UserPassProtocolEnum
        }

    def append(self, data: UserPassData) -> None:
        self.all[data.userpass_protocol].append(data=data)
        if data.username != None:
            self.usernames[data.userpass_protocol].append(data)
        if data.password != None:
            self.passwords[data.userpass_protocol].append(data)

    def get_all(self):
        all: List[UserPassData] = []
        for protocol in self.all:
            all.extend(self.all[protocol].all)
        return all