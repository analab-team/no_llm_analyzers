from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


class ProductCreation(BaseModel):
    product_name: str
    api_key: str = Field(default_factory=lambda: str(uuid4()))
    mode: str = Field(default="async")

    @field_validator("mode")
    def validate_option(cls, v):
        assert v in ["sync", "async"]
        return v


class Product(ProductCreation):
    product_id: UUID
