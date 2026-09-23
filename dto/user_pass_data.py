from dataclasses import dataclass
from dto.base_data import BaseData, AuthenticationProtocolEnum
from dto.enums import BasicTypeEnum, UserPassProtocolEnum, HTTPTypeEnum
from parsers.ftp_parser import FTPParser
from parsers.pop_parser import POPParser
from parsers.imap_parser import IMAPParser
from parsers.http_parser import HTTPParser
from parsers.smtp_parser import SMTPParser
from parsers.ldap_parser import LDAPParser
from typing import Optional




@dataclass
class UserPassData(BaseData):
    authentication_protocol: str = AuthenticationProtocolEnum.CLEARTEXT.value
    name: str = 'user:pass'
    username: str = None
    password: str = None
    userpass_protocol: UserPassProtocolEnum = None

    def __init__(self, packet, filename):
        super().__init__(packet=packet, filename=filename)

        self.layers_func = {
            "ldap": LDAPParser.try_parse,
            "pop": POPParser.try_parse,
            "imap": IMAPParser.try_parse,
            "ftp": FTPParser.try_parse,
            "http": HTTPParser.try_parse,
            "smtp": SMTPParser.try_parse
        }

        for layer, try_parse in self.layers_func.items():
            if layer in packet['layers']:
                try:
                    result = try_parse(packet)
                except Exception as e:
                    print(e)
                    result = None
                if result:
                    self.userpass_protocol, self.username, self.password = result
                    break
        if self.userpass_protocol is None:
            raise Exception("Cannot parse UserPassData from packet")

    def protocol(self) -> str:
        return self.userpass_protocol.value
    
    def key(self) -> str:
        return f"{self.protocol()}_{self.dst_ip}_{self.data()}"

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
        
    def is_user(self) -> bool:
        return True