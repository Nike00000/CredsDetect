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

    _results: Dict[str, List[ResponseNetNTLM]] = field(
        default_factory=dict,
        init=False
    )

    _must_update:Dict[str, bool] = field(
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
        self._must_update[data.session_id] = True

    def _merge_session(self, session_id:str):
        if session_id not in self._by_session:
            return
        self._results[session_id] = []
        session_list = sorted(self._by_session[session_id], key=lambda x: x.timestamp)
        challenge = None
        for ntlm_data in session_list:
            if isinstance(ntlm_data, ChallengeNetNTLM):
                challenge = ntlm_data
            else:
                if challenge is None:
                    ntlm_data.server_challenge = None
                    continue
                ntlm_data.server_challenge = challenge.challenge
                self._results[session_id].append(ntlm_data)

    def _update_all(self):
        for session_id in self._by_session:
            if self._must_update[session_id]:
                self._merge_session(session_id=session_id)
                self._must_update[session_id] = False
    
    def get_by_version(self, response_version: NTLMResponseEnum) -> UniqueContainer[ResponseNetNTLM]:
        self._update_all()
        hashes = UniqueContainer[ResponseNetNTLM]()
        for session_id in self._by_session:
            for response in self._results[session_id]:
                if response.version == response_version:
                    hashes.append(response)
        return hashes

    def get_all(self) -> List[ResponseNetNTLM]:
        self._update_all()
        all:List[ResponseNetNTLM] = []
        for resp_enum in NTLMResponseEnum:
            all.extend(self.get_by_version(resp_enum).all)
        return all