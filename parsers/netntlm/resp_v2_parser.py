from typing import Dict, Any, Optional
from dto.net_ntlm_data import RespV2NetNTLM
from parsers.base_parser import BaseParser

class Resp_v2_Parser(BaseParser):
    Y_FIELDS = ['ntlmssp.messagetype == 0x00000003']
    E_FIELDS = ['ntlmssp.auth.lmresponse',
                'ntlmssp.auth.username',
                'ntlmssp.auth.domain',
                'ntlmssp.ntlmv2_response.ntproofstr',
                'ntlmssp.ntlmv2_response'
                ]
                
    @classmethod
    def parse(cls, fields:Dict[str, str]) -> Optional[RespV2NetNTLM]:
        username   = fields.get('ntlmssp.auth.username') or None
        domain     = fields.get('ntlmssp.auth.domain') or 'unknown'
        lm         = fields.get('ntlmssp.auth.lmresponse') or ''
        ntproofstr = fields.get('ntlmssp.ntlmv2_response.ntproofstr') or None
        full       = fields.get('ntlmssp.ntlmv2_response') or ''

        # Признак v2: есть NTProofStr
        if not username or not ntproofstr:
            return None

        # NTProofStr всегда 16 байт = 32 hex
        if len(ntproofstr) != 32:
            return None

        if len(full) < 32:
            return None
        blob = full[32:]

        # Blob должен быть непустым, иначе это не валидный v2
        if not blob:
            return None

        base = BaseParser.get_base_dict(fields=fields)
        return RespV2NetNTLM(
            **base,
            username=username,
            domain=domain,
            lm_response=lm,
            ntproofstr=ntproofstr,
            blob=blob,
        )