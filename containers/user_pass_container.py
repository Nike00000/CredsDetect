from dataclasses import dataclass, field
from typing import List, Dict
from dto.user_pass_data import UserPassData
from containers.unique_container import UniqueContainer
from dto.enums import UserPassProtocolEnum
from containers.session_container import SessionContainer
from collections import deque
import copy

class UserPassContainer:

    def __init__(self):
        self.protocol_containers: Dict[UserPassProtocolEnum, SessionContainer] = {}

        for protocol in UserPassProtocolEnum:
            self.protocol_containers[protocol] = SessionContainer()

    session_container: SessionContainer[UserPassData] = SessionContainer()

    def append(self, data: UserPassData) -> None:
        self.protocol_containers[data.userpass_protocol].append(data=data)
    
    def get_all(self) -> Dict[UserPassProtocolEnum, UniqueContainer[UserPassData]]:
        all: Dict[UserPassProtocolEnum, UniqueContainer[UserPassData]] = {}
        for protocol in UserPassProtocolEnum:
            all[protocol] = UniqueContainer()
            if protocol not in self.protocol_containers:
                continue
            for sessions_id in self.protocol_containers[protocol].sessions:
                session_data = self.protocol_containers[protocol].sessions[sessions_id]

                i = 0
                while i < len(session_data):
                    data = session_data[i]
                    if data.is_full:
                        all[protocol].append(copy.deepcopy(data))
                        i = i + 1
                    if data.is_only_username and i + 1 < len(session_data):
                            next_data = session_data[i + 1]
                            if next_data.is_only_password:
                                local_data:UserPassData = copy.deepcopy(data)
                                local_data.password = next_data.password
                                all[protocol].append(local_data)
                                i = i + 2
                                continue
                    all[protocol].append(copy.deepcopy(data))
                    i = i + 1
        return all