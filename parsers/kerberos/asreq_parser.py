from typing import Dict, List, Optional
from dto.kerberos_data import AsreqKerberos
from dto.enums import KerberosEtypeEnum
from parsers.base_parser import BaseParser

class AsreqParser():
    Y_FIELDS = ['kerberos.msg_type == 10']
    E_FIELDS = ['kerberos.msg_type',
                'kerberos.CNameString',
                'kerberos.realm',
                'kerberos.msg_type',
                'kerberos.padata_type',
                'kerberos.padata_value']

    @staticmethod
    def _split_multi(raw: str) -> List[str]:
        """Разбивает агрегированное поле на части (|, запятая или одиночное)."""
        if '|' in raw:
            return raw.split('|')
        if ',' in raw:
            return raw.split(',')
        return [raw]

    @classmethod
    def _read_length(cls, data: bytes, pos: int) -> tuple[int, int]:
        """
        Читает DER-длину из data начиная с pos.
        Возвращает (length, new_pos).
        """
        first = data[pos]
        pos += 1

        if first < 0x80:
            # короткая форма: длина в одном байте
            return first, pos

        # длинная форма: младшие 7 бит = число байт длины
        n = first & 0x7F
        length = int.from_bytes(data[pos:pos + n], 'big')
        return length, pos + n

    @classmethod
    def _parse_padata_value(cls, hex_str:str) -> str:
        data = bytes.fromhex(hex_str)
        pos = 0

        if data[pos] != 0x30:
            return None

        pos += 1
        seq_len, pos = cls._read_length(data, pos)
        seq_end = pos + seq_len

        etype = None
        cipher = None

        while pos < seq_end:
            tag = data[pos]
            pos += 1
            length, pos = cls._read_length(data, pos)
            value = data[pos:pos + length]
            pos += length

            if tag == 0xA0:  # [0] etype
                # value = 02 01 XX → INTEGER длиной 1
                if len(value) >= 3 and value[0] == 0x02:
                    etype = value[2]
            elif tag == 0xA2:  # [2] cipher
                # value = 04 <len> <cipher>
                if len(value) >= 2 and value[0] == 0x04:
                    inner_len, inner_pos = cls._read_length(value, 1)
                    cipher = value[inner_pos:inner_pos + inner_len].hex()
            # tag 0xA1 (kvno) — игнорируем

        # проверка ПОСЛЕ цикла
        if etype is None or cipher is None:
            return None
        return {'etype': etype, 'cipher': cipher}
        
    @classmethod
    def parse(cls, fields:Dict[str, str]) -> Optional[AsreqKerberos]:
        msg_type = fields.get('kerberos.msg_type') or None
        if msg_type is None or msg_type != '10':
            return
        cname = fields.get('kerberos.CNameString') or None
        realm = fields.get('kerberos.realm') or None
        msg_type = fields.get('kerberos.msg_type') or None
        padata_type_raw = fields.get('kerberos.padata_type') or None
        padata_value_raw = fields.get('kerberos.padata_value') or None

        if not all((cname, realm, msg_type, padata_type_raw, padata_value_raw)):
            return None

        if msg_type != '10':
            return None

        padata_types = cls._split_multi(padata_type_raw)
        padata_values = cls._split_multi(padata_value_raw)

        if len(padata_types) != len(padata_values):
            return None

        cipher = None
        etype = None
        for ptype, pvalue in zip(padata_types, padata_values):
            if ptype.strip() == '2':
                parsed = cls._parse_padata_value(pvalue.strip())
                if parsed:
                    etype = parsed['etype']
                    cipher = parsed['cipher']
                    break

        if cipher is None or etype is None:
            return None

        # hashcat поддерживает только 17, 18, 23
        if etype not in (17, 18, 23):
            return None
        etype_enum = KerberosEtypeEnum(etype)
        base = BaseParser.get_base_dict(fields=fields)
        return AsreqKerberos(
            **base,
            cname=cname,
            realm=realm,
            etype=etype_enum,
            cipher=cipher
        )