from pydantic import BaseModel
from typing import List

class Vault(BaseModel):
    ignoring_banwords_input: List
    ignoring_banwords_output: List
    max_allowed_banwords_input: int
    max_allowed_banwords_output: int