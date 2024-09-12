from pydantic import BaseModel


class Vault(BaseModel):
    max_base64_matches_input: int
    max_base64_matches_output: int