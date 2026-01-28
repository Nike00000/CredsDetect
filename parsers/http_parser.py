from dto.enums import UserPassProtocolEnum, HTTPTypeEnum
import base64
    
class HTTPParser:

    @staticmethod
    def extract_proxy_authenticate(packet) -> str:
        try:
            authenticate = packet['layers']['http']['http_http_proxy_authenticate']
            return authenticate
        except:
            raise TypeError("http_http_proxy_authenticate don't found in packet")
        
    @staticmethod
    def extract_proxy_authorization(packet) -> str:
        try:
            authenticate = packet['layers']['http']['http_http_proxy_authorization']
            return authenticate
        except:
            raise TypeError("http_http_proxy_authorization don't found in packet")


    @staticmethod
    def extract_http_authorization(packet) -> str:
        try:
            authenticate = packet['layers']['http']['http_http_authorization']
            return authenticate
        except:
            raise TypeError("http_http_authorization don't found in packet")
        
    @staticmethod
    def get_type_auth(authorization:str) -> HTTPTypeEnum:
        auth_type = str(authorization).split(' ')[0]
        if 'Basic'.lower() in auth_type.lower():
            return HTTPTypeEnum.BASIC
        elif 'NTLM'.lower() in auth_type.lower():
            return HTTPTypeEnum.NTLM
        else:
            raise TypeError('Unknown type http authorization')
        
    @staticmethod
    def get_ntlm(authorization:str) -> HTTPTypeEnum:
        auth_data = str(authorization).split(' ')[1]
        auth_data_decode = base64.b64decode(auth_data).hex()
        return auth_data_decode
    
    @staticmethod
    def get_basic_auth_user(authorization:str) -> UserPassProtocolEnum:
        auth_data_encode = authorization.split(' ')[1]
        auth_data_decode = base64.b64decode(auth_data_encode).decode('utf-8')
        return auth_data_decode.split(':')[0]
    
    @staticmethod
    def get_basic_auth_pass(authorization:str) -> UserPassProtocolEnum:
        auth_data_encode = authorization.split(' ')[1]
        auth_data_decode = base64.b64decode(auth_data_encode).decode('utf-8')
        return auth_data_decode.split(':')[1]