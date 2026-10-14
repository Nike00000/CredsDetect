from typing import Dict
from dto.user_pass_data import UPData
from containers.unique_container import UniqueContainer
from dto.enums import UserPassProtocolEnum
from containers.session_container import SessionContainer
import copy

class UserPassContainer:

    def __init__(self):
        self.protocol_containers: Dict[UserPassProtocolEnum, SessionContainer] = {}
        self._results: Dict[UserPassProtocolEnum, Dict[str, UniqueContainer]] = {}
        self._must_update: Dict[UserPassProtocolEnum, Dict[str, bool]] = {}

        for protocol in UserPassProtocolEnum:
            self.protocol_containers[protocol] = SessionContainer()
            self._results[protocol] = {}
            self._must_update[protocol] = {}

    def append(self, data: UPData) -> None:
        self.protocol_containers[data.up_protocol].append(data=data)
        self._must_update[data.up_protocol][data.session_id] = True

    def _merge_up_session(self, up_protocol:UserPassProtocolEnum, session_id:str):
        self._must_update[up_protocol][session_id] = False
        self._results[up_protocol][session_id] = UniqueContainer[UPData]()
        session_data = sorted(self.protocol_containers[up_protocol].sessions[session_id], key=lambda x: x.timestamp)
        i = 0
        while i < len(session_data):
            data = session_data[i]
            if data.is_full:
                self._results[up_protocol][session_id].append(data)
                i = i + 1
                continue
            if data.is_only_username and i + 1 < len(session_data):
                    next_data = session_data[i + 1]
                    if next_data.is_only_password:
                        copy_data:UPData = copy.deepcopy(data)
                        copy_data.password = next_data.password
                        self._results[up_protocol][session_id].append(copy_data)
                        i = i + 2
                        continue
            self._results[up_protocol][session_id].append(data)
            i = i + 1

    def _update_all(self):
        for protocol in UserPassProtocolEnum:
            for session_id in self.protocol_containers[protocol].sessions:
                if self._must_update[protocol][session_id]:
                    self._merge_up_session(up_protocol=protocol, session_id=session_id)

    def get_all(self) -> Dict[UserPassProtocolEnum, UniqueContainer]:
        self._update_all()
        all: Dict[UserPassProtocolEnum, UniqueContainer] = {}
        for protocol in UserPassProtocolEnum:
            all[protocol] = UniqueContainer[UPData]()
            for session_id in self.protocol_containers[protocol].sessions:
                all[protocol].extend(self._results[protocol][session_id].all)
        return all