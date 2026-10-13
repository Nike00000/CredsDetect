from dataclasses import dataclass
from dto.base_data import BaseData
from dto.enums import AuthenticationProtocolEnum
from dto.enums import UserPassProtocolEnum

@dataclass
class UPData(BaseData):
    authentication_protocol: str = AuthenticationProtocolEnum.CLEARTEXT.value
    name: str = 'user:pass'
    username: str = None
    password: str = None
    up_protocol: UserPassProtocolEnum = None

    @property
    def protocol(self) -> str:
        return self.up_protocol.value

    @property
    def key(self) -> str:
        return f"{self.protocol}_{self.dst_ip}_{self.data}"

    @property
    def is_full(self):
        if self.username and self.password:
            return True
        return False

    @property
    def is_only_username(self):
        if self.username and not self.password:
            return True
        return False

    @property
    def is_only_password(self):
        if not self.username and self.password:
            return True
        return False

    @property
    def data(self) -> str:
        text = 'no data'
        if self.username == None:
            if self.password != None:
                text = f'password is {self.password}'
        else:
            if self.password == None:
                text = f'username is {self.username}'
            else:
                text = f'{self.username} : {self.password}'
        return text

    @property    
    def is_user(self) -> bool:
        return True