from clickhouse_connect.driver.client import Client
from crud import get_db_client
from crud.request_result import add_new_request_result, add_new_response_result
from fastapi import APIRouter, Depends, HTTPException, status
from models.product import Product
from routers import verify_api_key
from schemas.analyze import InputRequest, OutputRequest, OutputResponse
from services.analyzer import Analyzer
from services.vault_manager import Vault, vault_manager

monitoring_router = APIRouter(prefix="/analyze")

analyzers_service = Analyzer()


def get_vault_for_product(product: Product) -> Vault:
    try:
        product_vault = vault_manager.get_vault(product_id=product.product_id)
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Product {product.product_name} has not vault for this analyzer.",
        )

    return product_vault


@monitoring_router.post("/input", status_code=status.HTTP_200_OK)
async def input(
    input_request: InputRequest,
    client: Client = Depends(get_db_client),
    product: Product = Depends(verify_api_key),
):
    product_vault = get_vault_for_product(product)

    result = analyzers_service.analyze_input(
        text=input_request.input_text,
        vault=product_vault,
    )

    if result.reasons:
        serialized_reasons = [reason.model_dump_json() for reason in result.reasons]
    else:
        serialized_reasons = None

    add_new_request_result(
        client=client,
        request_id=input_request.request_id,
        metric=result.metric,
        reject_flg=result.reject_flg,
        reasons=serialized_reasons,
        analyzer_name=input_request.analyzer_name,
    )


@monitoring_router.post(
    "/output",
    status_code=status.HTTP_200_OK,
    response_model=OutputResponse,
)
async def output(
    output_request: OutputRequest,
    client: Client = Depends(get_db_client),
    product: Product = Depends(verify_api_key),
):
    product_vault = get_vault_for_product(product)

    result = analyzers_service.analyze_input(
        text=output_request.output_text,
        vault=product_vault,
    )

    if result.reasons:
        serialized_reasons = [reason.model_dump_json() for reason in result.reasons]
    else:
        serialized_reasons = None

    add_new_response_result(
        client=client,
        response_id=output_request.response_id,
        metric=result.metric,
        reject_flg=result.reject_flg,
        reasons=serialized_reasons,
        analyzer_name=output_request.analyzer_name,
    )

    return OutputResponse(reject_flg=result.reject_flg)
