from dataclasses import dataclass, field
from typing import overload, Union, List, Dict
from dto.net_ntlm_data import ResponseNetNTLM, ChallengeNetNTLM, NTLMResponseEnum
from containers.unique_container import UniqueContainer
from dto.enums import NTLMResponseEnum


@dataclass
class NTLMContainer:

    _by_session: Dict[str, List[Union[ChallengeNetNTLM, ResponseNetNTLM]]] = field(
        default_factory=dict,
        init=False
    )

    @overload
    def append(self, data: ChallengeNetNTLM) -> None: ...

    @overload
    def append(self, data: ResponseNetNTLM) -> None: ...

    def append(self, data: Union[ChallengeNetNTLM, ResponseNetNTLM]) -> None:
        session_list = self._by_session.setdefault(data.session_id, [])
        session_list.append(data)
    
    def merge_to_hash(self, type_response: NTLMResponseEnum) -> UniqueContainer[ResponseNetNTLM]:
        hashes = UniqueContainer[ResponseNetNTLM]()
        for session_id in self._by_session:
            session_list = sorted(self._by_session[session_id], key=lambda x: x.timestamp)
            challenge = None
            for data in session_list:
                if isinstance(data, ChallengeNetNTLM):
                    challenge = data
                else:
                    if challenge is None:
                        data.server_challenge = None
                        continue
                    if type_response == data.version:
                        data.server_challenge = challenge.challenge
                        hashes.append(data)
        return hashes

    def get_all(self) -> List[ResponseNetNTLM]:
        all:List[ResponseNetNTLM] = []
        for resp_enum in NTLMResponseEnum:
            all.extend(self.merge_to_hash(resp_enum).all)
        return all
