from typing import Dict, Any, Optional
from dto.net_ntlm_data import ChallengeNetNTLM
from parsers.base_parser import BaseParser

class ChallengeNTLMParser(BaseParser):
    Y_FIELDS = ['ntlmssp.messagetype == 0x00000002']
    E_FIELDS = ['ntlmssp.ntlmserverchallenge']

    @classmethod
    def parse(cls, fields:Dict[str, str]) -> Optional[ChallengeNetNTLM]:
        challenge = fields.get('ntlmssp.ntlmserverchallenge') or None
        if not challenge:
            return None
        base = BaseParser.get_base_dict(fields=fields)
        return ChallengeNetNTLM(
            **base,
            challenge=challenge,
        )