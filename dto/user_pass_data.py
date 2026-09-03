from dataclasses import dataclass
from dto.base_data import BaseData, AuthenticationProtocolEnum
from dto.enums import BasicTypeEnum, UserPassProtocolEnum, HTTPTypeEnum
from parsers.ftp_parser import FTPParser
from parsers.pop_parser import POPParser
from parsers.imap_parser import IMAPParser
from parsers.http_parser import HTTPParser
from parsers.smtp_parser import SMTPParser
from parsers.ldap_parser import LDAPParser
@dataclass
class UserPassData(BaseData):
    authentication_protocol: str = AuthenticationProtocolEnum.CLEARTEXT.value
    name: str = 'user:pass'
    username: str = None
    password: str = None
    userpass_protocol: UserPassProtocolEnum = None
    def __init__(self, packet, filename):
        super().__init__(packet=packet, filename=filename)
        #LDAP
        try:
            self.userpass_protocol = UserPassProtocolEnum.LDAP
            self.username = LDAPParser.get_username(packet=packet)
            self.password = LDAPParser.get_password(packet=packet)
            if not (self.username and self.password):
                raise TypeError('No simple data for LDAP protocol')
            return
        except Exception as e:
            pass

        #POP
        try:
            self.userpass_protocol = UserPassProtocolEnum.POP
            command = POPParser.get_command(packet=packet)
            if command == BasicTypeEnum.USERNAME:
                self.username = POPParser.get_arg(packet=packet)
            elif command == BasicTypeEnum.PASSWORD:
                self.password = POPParser.get_arg(packet=packet)
            else:
                raise TypeError('Unknown command for POP protocol')
            return
        except Exception as e:
            pass
        #IMAP
        try:
            self.userpass_protocol = UserPassProtocolEnum.IMAP
            try:
                self.username = IMAPParser.get_username(packet=packet)
            except:
                pass
            try:
                self.password = IMAPParser.get_password(packet=packet)
            except:
                pass
            if self.username != None or self.password != None:
                return
            else:
                raise TypeError('Auth IMAP data not found')
        except Exception as e:
            pass
        #SMTP
        try:
            self.userpass_protocol = UserPassProtocolEnum.SMTP
            try:
                self.username = SMTPParser.get_username(packet=packet)
                return
            except:
                pass
            try:
                self.password = SMTPParser.get_password(packet=packet)
                return
            except:
                pass
        except Exception as e:
            pass
        #FTP
        try:
            self.userpass_protocol = UserPassProtocolEnum.FTP
            command = FTPParser.get_command(packet=packet)
            if command == BasicTypeEnum.USERNAME:
                self.username = FTPParser.get_arg(packet=packet)
            elif command == BasicTypeEnum.PASSWORD:
                self.password = FTPParser.get_arg(packet=packet)
            else:
                raise TypeError('Unknown command for FTP protocol')
            return
        except Exception as e:
            pass

        #HTTP
        try:
            authorization = None
            try:
                authorization = HTTPParser.extract_proxy_authenticate(packet=packet)
                self.userpass_protocol = UserPassProtocolEnum.HTTP_ProxyAuthenticate
            except:
                pass
            try:
                authorization = HTTPParser.extract_proxy_authorization(packet=packet)
                self.userpass_protocol = UserPassProtocolEnum.HTTP_ProxyAuthorization
            except:
                pass
            try:
                authorization = HTTPParser.extract_http_authorization(packet=packet)
                self.userpass_protocol = UserPassProtocolEnum.HTTP_Authorization
            except:
                pass
            if authorization == None:
                raise TypeError("NTLM data don't found in packet")
            autorization_type = HTTPParser.get_type_auth(authorization=authorization)
            if autorization_type == HTTPTypeEnum.BASIC:
                self.username = HTTPParser.get_basic_auth_user(authorization=authorization)
                self.password = HTTPParser.get_basic_auth_pass(authorization=authorization)
            else:
                raise TypeError("Unsupported type http authorization")
            return
        except Exception as e:
            pass
        raise TypeError("Unsupported type UserPass authorization")

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