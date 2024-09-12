from typing import List
from uuid import UUID

from clickhouse_connect.driver.client import Client
from models.request_result import RequestResult
from models.response_result import ResponseResult


def add_new_request_result(
    client: Client,
    request_id: UUID,
    metric: float,
    reject_flg: bool,
    reasons: List[str] | None,
    analyzer_name: str,
) -> RequestResult:
    stmt = """
    INSERT INTO request_analysis_results (request_id, analyzer_name, metric, reject_flg, reasons)
    VALUES (%(request_id)s, %(analyzer_name)s, %(metric)s, %(reject_flg)s, %(reasons)s)
    """
    request_result = RequestResult(
        request_id=request_id,
        metric=metric,
        analyzer_name=analyzer_name,
        reject_flg=reject_flg,
        reasons=reasons,
    )

    client.query(stmt, parameters=request_result.model_dump())

    return request_result


def add_new_response_result(
    client: Client,
    response_id: UUID,
    metric: float,
    reject_flg: bool,
    reasons: List[str] | None,
    analyzer_name: str,
) -> ResponseResult:
    stmt = """
    INSERT INTO response_analysis_results (response_id, analyzer_name, metric, reject_flg, reasons)
    VALUES (%(response_id)s, %(analyzer_name)s, %(metric)s, %(reject_flg)s, %(reasons)s)
    """
    request_result = ResponseResult(
        response_id=response_id,
        metric=metric,
        analyzer_name=analyzer_name,
        reject_flg=reject_flg,
        reasons=reasons,
    )

    client.query(stmt, parameters=request_result.model_dump())

    return request_result
