from pydantic import BaseModel


class VaultExample(BaseModel):
    vault_schema: str
