from core.config import main_config
from crud import get_db_client
from crud.product import get_product
from fastapi import Depends, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
from models.product import Product

API_KEY_NAME = "api_key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

ADMIN_API_KEY = main_config.admin_api_key


def verify_api_key(
    api_key: str = Security(api_key_header), client=Depends(get_db_client)
) -> Product:
    if not api_key:
        raise HTTPException(status_code=403, detail="API key is missing")
    api_key_record = get_product(client, api_key=api_key)
    if not api_key_record:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return api_key_record


def verify_admin_api_key(api_key: str = Security(api_key_header)):
    if not api_key:
        raise HTTPException(status_code=403, detail="API key is missing")

    if ADMIN_API_KEY != api_key:
        raise HTTPException(status_code=403, detail="Invalid API key")
