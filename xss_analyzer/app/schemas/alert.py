from pydantic import BaseModel


class Alert(BaseModel):
    api_key: str
    analyzer_name: str
    metric: float