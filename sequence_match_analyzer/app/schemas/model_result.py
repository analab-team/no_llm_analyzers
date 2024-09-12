from typing import List

from pydantic import BaseModel


class Reason(BaseModel):
    start: int
    stop: int
    additional_metric: float | None = None


class ModelResult(BaseModel):
    metric: float
    reasons: List[Reason] | None = None
    reject_flg: bool
