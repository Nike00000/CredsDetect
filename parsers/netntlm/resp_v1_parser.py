from typing import Dict, Any, Optional
from dto.net_ntlm_data import RespV1ESSNetNTLM, RespV1NetNTLM
from parsers.base_parser import BaseParser

class Resp_v1_Parser(BaseParser):
    Y_FIELDS = ['ntlmssp.messagetype == 0x00000003']
    E_FIELDS = ['ntlmssp.auth.username',
                'ntlmssp.auth.domain',
                'ntlmssp.auth.lmresponse',    # client_challenge + нули (ESS)
                'ntlmssp.auth.ntresponse',
                ]

    @classmethod
    def parse(cls, fields:Dict[str, str]) -> Optional[RespV1ESSNetNTLM]:

        username = fields.get('ntlmssp.auth.username') or 'unknown'
        domain = fields.get('ntlmssp.auth.domain') or 'unknown'
        lm = fields.get('ntlmssp.auth.lmresponse') or None
        nt = fields.get('ntlmssp.auth.ntresponse') or None

        # NTLMv1 ESS: ntresponse ровно 24 байта (48 hex)
        if not nt or len(nt) != 48:
            return None

        # LM response для ESS: 24 байта, последние 16 — нули
        if not lm or len(lm) != 48:
            return None

        client_challenge = lm[:16]
        if lm[16:] != '0' * 32: # Clear type v1
            return RespV1NetNTLM(
                **base,
                username=username,
                domain=domain,
                lm_response=lm,
                nt_response=nt,
            )

        base = BaseParser.get_base_dict(fields=fields)
        return RespV1ESSNetNTLM(
            **base,
            username=username,
            domain=domain,
            lm_response=lm,
            nt_response=nt,
            client_challenge=client_challenge,
        )