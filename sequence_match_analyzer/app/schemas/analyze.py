from uuid import UUID

from pydantic import BaseModel


class InputRequest(BaseModel):
    request_id: UUID
    input_text: str
    analyzer_name: str


class OutputRequest(BaseModel):
    response_id: UUID
    output_text: str
    analyzer_name: str


class OutputResponse(BaseModel):
    reject_flg: bool
