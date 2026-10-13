class NTLMParser:
   
    NTLMSSP_SIGNATURE = "4e544c4d535350"
    CHALLENGE_POSITION = 24
    CHALLENGE_LENGTH = 8

    @staticmethod
    def find_int(data_bytes: bytes, position: int, length: int) -> int:
        """Извлекает целое число из байтовой строки"""
        value_raw = data_bytes[position:(position + length)]
        return int.from_bytes(value_raw, 'little')
    
    @staticmethod
    def find_hex_str(data_bytes: bytes, position: int, length: int) -> str:
        """Извлекает строку в hex-формате"""
        return data_bytes[position:(position + length)].hex()
    
    @staticmethod
    def decode_utf16le(data_bytes: bytes, position: int, length: int) -> str:
        """Декодирует UTF-16LE строку"""
        return data_bytes[position:(position + length)].decode('utf-16-le', errors='ignore')
    
    @classmethod
    def get_lm_response(cls, payload_bytes: bytes) -> str:
        """Получает LM Response"""
        return cls._get_encoded_field(payload_bytes, 12, 2, 16, 4, is_unicode=False)
    
    @classmethod
    def get_nt_response(cls, payload_bytes: bytes) -> str:
        """Получает NT Response"""
        return cls._get_encoded_field(payload_bytes, 20, 2, 24, 4, is_unicode=False)
    
    @classmethod
    def get_domain(cls, payload_bytes: bytes) -> str:
        """Получает домен"""
        return cls._get_encoded_field(payload_bytes=payload_bytes,
                                      len_pos=28,
                                      len_size=2,
                                      offset_pos=32,
                                      offset_size=4,
                                      is_unicode=True)
    
    @classmethod
    def get_username(cls, payload_bytes: bytes) -> str:
        """Получает имя пользователя"""
        return cls._get_encoded_field(payload_bytes, 36, 2, 40, 4, is_unicode=True)
    
    @classmethod
    def get_workstation(cls, payload_bytes: bytes) -> str:
        """Получает имя рабочей станции"""
        return cls._get_encoded_field(payload_bytes, 44, 2, 48, 4, is_unicode=True)
    
    @classmethod
    def get_challenge(cls, payload_bytes: str) -> str:
        """Получает challenge"""
        challenge_bytes = payload_bytes[cls.CHALLENGE_POSITION:cls.CHALLENGE_POSITION + cls.CHALLENGE_LENGTH]
        return challenge_bytes.hex()

        return payload_str[48:48 + cls.CHALLENGE_LENGTH]
    
    @classmethod
    def _get_encoded_field(cls, payload_bytes: bytes, 
                          len_pos: int,
                          len_size: int,
                          offset_pos: int,
                          offset_size: int,
                          is_unicode: bool = True) -> str:
        """Внутренний метод для получения поля с указанной кодировкой"""
        try:
            length = cls.find_int(payload_bytes, len_pos, len_size)
            offset = cls.find_int(payload_bytes, offset_pos, offset_size)
            
            if length == 0 or offset == 0:
                return ""
            
            if is_unicode:
                return cls.decode_utf16le(payload_bytes, offset, length)
            else:
                return cls.find_hex_str(payload_bytes, offset, length)
                
        except Exception:
            return ""
    
    @classmethod
    def get_message_type(cls, payload_bytes: bytes) -> int:
        """Получает тип NTLM сообщения"""
        return cls.find_int(payload_bytes, 8, 4)
    
    @classmethod
    def extract_payload_str(cls, packet) -> bytes:
        payload = packet['layers']['tcp']['tcp_tcp_payload']
        payload_str = str(payload).replace(':', '')
        offset = payload_str.find(cls.NTLMSSP_SIGNATURE)
        if offset == -1:
            return None
            
        payload_str = payload_str[offset:]
        return payload_str

    @classmethod
    def extract_payload_bytes(cls, packet) -> bytes:
        payload = packet['layers']['tcp']['tcp_tcp_payload']
        payload_str = str(payload).replace(':', '')
        offset = payload_str.find(cls.NTLMSSP_SIGNATURE)
        if offset == -1:
            return None
            
        payload_str = payload_str[offset:]
        payload_bytes = bytes.fromhex(payload_str)
        return payload_bytes