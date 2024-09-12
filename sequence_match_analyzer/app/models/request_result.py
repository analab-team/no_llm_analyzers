from typing import List
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class RequestResult(BaseModel):
    result_id: UUID = Field(default_factory=lambda: uuid4())
    request_id: UUID
    analyzer_name: str
    metric: float
    reject_flg: bool
    reasons: List[str] | None
