from pydantic import BaseModel
from typing import List

class Vault(BaseModel):
    threshold_input: float
    threshold_output: float