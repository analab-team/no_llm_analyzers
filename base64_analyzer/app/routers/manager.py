import json

from fastapi import APIRouter, Depends, status
from models.product import Product
from routers import verify_api_key
from schemas.vault import VaultExample
from services.vault_manager import Vault, vault_manager

manager_router = APIRouter(prefix="/manager")


@manager_router.post("/add_vault", status_code=status.HTTP_201_CREATED)
async def add_vault(
    vault: Vault,
    product: Product = Depends(verify_api_key),
):
    vault_manager.add_vault(product.product_id, vault)


@manager_router.get(
    "/vault_example",
    status_code=status.HTTP_200_OK,
    response_model=VaultExample,
)
async def get_vault_example():
    str_schema = json.dumps(Vault.model_json_schema())
    return VaultExample(vault_schema=str_schema)
