from pydantic import BaseModel
from typing import List

class Vault(BaseModel):
    max_allowed_words_matched_input: int
    max_allowed_words_matched_output: int