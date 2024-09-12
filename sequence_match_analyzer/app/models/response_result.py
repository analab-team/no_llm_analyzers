from typing import List
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class ResponseResult(BaseModel):
    result_id: UUID = Field(default_factory=lambda: uuid4())
    response_id: UUID
    analyzer_name: str
    metric: float
    reject_flg: bool
    reasons: List[str] | None
