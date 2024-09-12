from pydantic import BaseModel
from typing import List

class Vault(BaseModel):
    use_regex_input: bool
    use_regex_output: bool
    use_payload_signature_input: bool
    use_payload_signature_output: bool
    use_bs4_input: bool
    use_bs4_output: bool
    max_allowed_xss_input: int
    max_allowed_xss_output: int