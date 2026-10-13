from typing import Optional, Dict
from parsers.base_parser import BaseParser
from dto.kerberos_data import TgsrepKerberos
from dto.enums import KerberosEtypeEnum

class TgsrepKerberosParser(BaseParser):

    Y_FIELDS = ['kerberos.msg_type == 13']
    E_FIELDS = ['kerberos.msg_type',
                'kerberos.CNameString',
                'kerberos.realm',
                'kerberos.SNameString',
                'kerberos.etype',
                'kerberos.encryptedKDCREPData_cipher',
                ]

    @classmethod
    def parse(cls, fields: Dict[str, str]) -> Optional[TgsrepKerberos]:
        msg_type = fields.get('kerberos.msg_type') or None
        if msg_type is None or msg_type != '13':
            return
        cname = fields.get('kerberos.CNameString') or None
        realm = fields.get('kerberos.realm') or None
        spn_raw = fields.get('kerberos.SNameString') or None
        etype_raw = fields.get('kerberos.etype') or None
        cipher = fields.get('kerberos.encryptedKDCREPData_cipher') or None

        if not all((cname, realm, spn_raw, etype_raw, cipher)):
            return None

        etype = cls._first_etype(etype_raw)
        if etype is None or etype not in (17, 18, 23):
            return None

        etype_enum = KerberosEtypeEnum(etype)
        spn = cls._normalize_spn(spn_raw)
        if not spn:
            return None

        base = BaseParser.get_base_dict(fields=fields)
        return TgsrepKerberos(
            **base,
            cname=cname,
            realm=realm,
            sname=spn,
            etype=etype_enum,
            cipher=cipher,
        )

    @staticmethod
    def _first_etype(raw: str) -> Optional[int]:
        """Первый etype в списке — enc-part TGS-REP."""
        first = raw.replace('|', ',').split(',')[0].strip()
        try:
            return int(first)
        except (ValueError, IndexError):
            return None

    @staticmethod
    def _normalize_spn(raw: str) -> Optional[str]:
        """
        SPN приходит как 'service/host' (иногда с несколькими частями).
        SNameString — список через |, склеиваем в SPN.
        """
        parts = [p.strip() for p in raw.replace(',', '|').split('|') if p.strip()]
        if not parts:
            return None
        # service/host — стандартный формат SPN
        return '/'.join(parts)