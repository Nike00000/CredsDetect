from dataclasses import dataclass, field
from typing import List, overload, Union
from dto.user_pass_data import UserPassData
from dto.net_ntlm_data import ChallengeNetNTLM, ResponseNetNTLM
from dto.kerberos_data import AsreqKerberos, AsrepKerberos, TgsrepKerberos
from containers.ntlm_container import NTLMContainer
from containers.kerberos_container import KerberosContainer
from containers.user_pass_container import UserPassContainer
@dataclass
class ResultsContainer:
    ntlm_container: NTLMContainer = field(default_factory=NTLMContainer)
    kerberos_container: KerberosContainer = field(default_factory=KerberosContainer)
    user_pass_container: UserPassContainer = field(default_factory=UserPassContainer)

    @overload
    def append(self, data: AsreqKerberos) -> None: ...
    @overload
    def append(self, data: AsrepKerberos) -> None: ...
    @overload
    def append(self, data: TgsrepKerberos) -> None: ...
    @overload
    def append(self, data: ChallengeNetNTLM) -> None: ...
    @overload
    def append(self, data: ResponseNetNTLM) -> None: ...
    @overload
    def append(self, data: UserPassData) -> None: ...
    
    def append(self, data: Union[AsreqKerberos,
                                 AsreqKerberos,
                                 TgsrepKerberos,
                                 ResponseNetNTLM,
                                 ChallengeNetNTLM,
                                 UserPassData]) -> None:
        match data:
            case AsreqKerberos() | AsrepKerberos() | TgsrepKerberos():
                self.kerberos_container.append(data)
            case ChallengeNetNTLM() | ResponseNetNTLM():
                self.ntlm_container.append(data)
            case UserPassData():
                self.user_pass_container.append(data)
            case _:
                raise TypeError(f"Unsupported type: {type(data)}")

    def extend(self, list_obj):
        for obj in list_obj:
            self.append(obj)

    def get_all(self):
        all_results = self.user_pass_container.get_all()
        all_results.extend(self.ntlm_container.get_all())
        all_results.extend(self.kerberos_container.get_all())
        return all_results
    