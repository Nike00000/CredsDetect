from dataclasses import dataclass, field
from typing import overload, Union, List, Dict
from dto.net_ntlm_data import ResponseNetNTLM, ChallengeNetNTLM, NTLMResponseEnum, HashNetNTLM
from containers.unique_container import UniqueContainer
from dto.enums import NTLMResponseEnum


@dataclass
class NTLMContainer:
    challenges: List[ChallengeNetNTLM] = field(default_factory=list)

    responses: Dict[NTLMResponseEnum, UniqueContainer[ResponseNetNTLM]] = field(
        default_factory=dict,
        init=False
    )
    _by_session: Dict[str, List[Union[ChallengeNetNTLM, ResponseNetNTLM]]] = field(
        default_factory=dict,
        init=False
    )

    def __post_init__(self) -> None:
        self.responses = {
            member: UniqueContainer[ResponseNetNTLM]()
            for member in NTLMResponseEnum
        }


    @overload
    def append(self, data: ChallengeNetNTLM) -> None: ...

    @overload
    def append(self, data: ResponseNetNTLM) -> None: ...

    def append(self, data: Union[ChallengeNetNTLM, ResponseNetNTLM]) -> None:
        session_list = self._by_session.setdefault(data.session_id, [])
        session_list.append(data)
        match data:
            case ChallengeNetNTLM():
                self.challenges.append(data)
            case ResponseNetNTLM():
                self.responses[data.version()].append(data)
            case _:
                raise TypeError(f"Unsupported type: {type(data)}")
    
    def get_hash(self, type_response: NTLMResponseEnum) -> UniqueContainer[HashNetNTLM]:
        hashes = UniqueContainer[HashNetNTLM]()
        for session_id in self._by_session:
            session_list = sorted(self._by_session[session_id], key=lambda x: x.timestamp)
            challenge = None
            for data in session_list:
                if isinstance(data, ChallengeNetNTLM):
                    challenge = data
                elif isinstance(data, ResponseNetNTLM):
                    if challenge is None:
                        continue
                    if type_response == data.version():
                        hashes.append(HashNetNTLM(challenge, data))
        return hashes

    def get_all(self):
        all_list: List[Union[ChallengeNetNTLM, ResponseNetNTLM]] = []
        all_list.extend(self.challenges)
        all_list.extend(self.responses[NTLMResponseEnum.RESPONSE_V1].all)
        all_list.extend(self.responses[NTLMResponseEnum.RESPONSE_V2].all)
        return all_list
