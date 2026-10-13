from typing import Dict, Any
class BaseParser:
    Y_FIELDS = []
    E_FIELDS = ['frame.time_epoch',
                'frame.number',
                'eth.src',
                'eth.dst',
                'ip.src',
                'ip.dst',
                'tcp.srcport',
                'tcp.dstport']

    _FIELD_MAP = {
        'frame.time_epoch':'timestamp',
        'frame.number': 'number',
        'eth.src': 'src_mac',
        'eth.dst': 'dst_mac',
        'ip.src':'src_ip',
        'ip.dst':'dst_ip',
        'tcp.srcport': 'src_port',
        'tcp.dstport': 'dst_port'
    }

    @classmethod
    def get_base_dict(cls, fields:Dict[str,Any]) -> Dict[str, Any]:
        result:Dict[str,Any] = {}
        for e_field in cls.E_FIELDS:
            name_key = cls._FIELD_MAP[e_field]
            result[name_key] = fields.get(e_field) or ''
        return result