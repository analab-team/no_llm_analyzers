from typing import Dict
from uuid import UUID

from models.vault import Vault


class VaultManager:
    def __init__(self) -> None:
        self.vaults: Dict[str, Vault] = dict()

    def add_vault(self, product_id: UUID, vault: Vault):
        self.vaults[str(product_id)] = vault

    def get_vault(self, product_id: UUID) -> Vault:
        return self.vaults[str(product_id)]

    def delete_vault(self, product_id: UUID):
        _ = self.vaults.pop(str(product_id))


vault_manager = VaultManager()
