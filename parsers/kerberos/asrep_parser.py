from typing import Dict, List, Optional
from dto.kerberos_data import AsrepKerberos
from dto.enums import KerberosEtypeEnum
from parsers.base_parser import BaseParser

class AsrepParser():
    Y_FIELDS = ['kerberos.msg_type == 11']
    E_FIELDS = ['kerberos.msg_type',
                'kerberos.CNameString',
                'kerberos.realm',
                'kerberos.etype',
                'kerberos.encryptedKDCREPData_cipher',
    ]

    @staticmethod
    def _extract_first_etype(raw: str) -> Optional[int]:
        """
        Извлекает первый etype из строки.
        Поддерживает разделители '|' и ','.
        """
        # нормализуем разделители
        normalized = raw.replace('|', ',').strip()
        first = normalized.split(',')[0].strip()
        try:
            return int(first)
        except (ValueError, IndexError):
            return None
        
    @classmethod
    def parse(cls, fields:Dict[str, str]) -> Optional[AsrepKerberos]:
        msg_type = fields.get('kerberos.msg_type') or None
        if msg_type is None or msg_type != '11':
            return
        cname = fields.get('kerberos.CNameString') or None
        realm = fields.get('kerberos.realm') or None
        etype_raw = fields.get('kerberos.etype') or None
        cipher = fields.get('kerberos.encryptedKDCREPData_cipher') or None

        if not all((cname, realm, etype_raw, cipher)):
            return None

        # etype приходит списком через | (или ,): "23|3" → берём первое
        etype = cls._extract_first_etype(etype_raw)
        if etype is None:
            return None

        # hashcat поддерживает только 17, 18, 23
        if etype not in (17, 18, 23):
            return None
        etype_enum = KerberosEtypeEnum(etype)
        base = BaseParser.get_base_dict(fields=fields)
        return AsrepKerberos(
            **base,
            cname=cname,
            realm=realm,
            etype=etype_enum,
            cipher=cipher,
        )