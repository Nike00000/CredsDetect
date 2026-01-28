from dataclasses import dataclass, field
from typing import overload, Union, List, Dict
from dto.kerberos_data import AsreqKerberos, AsrepKerberos, TgsrepKerberos, KerberosEtypeEnum
from containers.unique_container import UniqueContainer

@dataclass
class KerberosContainer:

    asreq: Dict[KerberosEtypeEnum, UniqueContainer[AsreqKerberos]] = field(
        default_factory=dict,
        init=False
    )

    asrep: Dict[KerberosEtypeEnum, UniqueContainer[AsreqKerberos]] = field(
        default_factory=dict,
        init=False
    )

    tgsrep: Dict[KerberosEtypeEnum, UniqueContainer[AsreqKerberos]] = field(
        default_factory=dict,
        init=False
    )

    def __post_init__(self) -> None:
        self.asreq = {
            member: UniqueContainer[AsreqKerberos]()
            for member in KerberosEtypeEnum
        }
        self.asrep = {
            member: UniqueContainer[AsrepKerberos]()
            for member in KerberosEtypeEnum
        }
        self.tgsrep = {
            member: UniqueContainer[TgsrepKerberos]()
            for member in KerberosEtypeEnum
        }

    @overload
    def append(self, data: AsreqKerberos) -> None: ...
    @overload
    def append(self, data: AsrepKerberos) -> None: ...
    @overload
    def append(self, data: TgsrepKerberos) -> None: ...

    def append(self, data: Union[AsreqKerberos, AsrepKerberos, TgsrepKerberos]) -> None:
        match data:
            case AsreqKerberos():
                self.asreq[data.etype].append(data=data)
            case AsrepKerberos():
                self.asrep[data.etype].append(data=data)
            case TgsrepKerberos():
                self.tgsrep[data.etype].append(data=data)
            case _:
                raise TypeError(f"Unsupported type: {type(data)}")

    def extend(self, list_obj: List[AsreqKerberos | AsrepKerberos]):
        for obj in list_obj:
            self.append(obj)

    def get_all(self):
        all:List[Union[AsrepKerberos, AsrepKerberos, TgsrepKerberos]] = []
        for krb_type in KerberosEtypeEnum:
            all.extend(self.asreq[krb_type].all)
            all.extend(self.asrep[krb_type].all)
            all.extend(self.tgsrep[krb_type].all)
        return all
    
