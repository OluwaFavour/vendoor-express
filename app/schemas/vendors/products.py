from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any, Generic, TypeVar
from uuid import UUID
from fastapi import Form, UploadFile
from pydantic import BaseModel, ConfigDict, Field

from app.schemas.users import User


class ProductBase(BaseModel):
    name: str
    category: str
    price: Annotated[Decimal, Field(gt=0, decimal_places=2)]
    description: str
    specification: str


class ProductCreate(ProductBase):
    model_config: ConfigDict = ConfigDict(extra="forbid")


class ProductCreateForm:
    def __init__(
        self,
        name: Annotated[str, Form()],
        category: Annotated[str, Form()],
        price: Annotated[Decimal, Form(gt=0, decimal_places=2)],
        description: Annotated[str, Form()],
        specification: Annotated[str, Form()],
        image: UploadFile,
    ):

        self.name = name
        self.category = category
        self.price = price
        self.description = description
        self.specification = specification
        self.image = image

    def model_dump(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "price": self.price,
            "description": self.description,
            "specification": self.specification,
            "image": self.image,
        }


class Product(ProductBase):
    model_config: ConfigDict = ConfigDict(from_attributes=True)
    image_url: str | None
    id: UUID
    created_at: datetime

    vendor: User


class ProductWithoutUser(ProductBase):
    model_config: ConfigDict = ConfigDict(from_attributes=True)
    image_url: str | None
    id: UUID
    created_at: datetime


class ProductWebhookContext(BaseModel):
    custom: dict[str, str]


class ProductWebhookData(BaseModel):
    public_id: str
    secure_url: str
    context: ProductWebhookContext


class ProductResponse(BaseModel):
    message: str
    product: Product


class ProductsResponse(BaseModel):
    products: list[Product]
    total: int
    page: int
    limit: int
    has_next: bool
    has_prev: bool


T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    items: list[T]
    total: Annotated[int | None, Field(ge=0, description="The total number of items")]
    next_cursor: Annotated[
        datetime | None,
        Field(description="The cursor for the next page, uses the 'created_at' field"),
    ] = None
    previous_cursor: Annotated[
        datetime | None,
        Field(
            description="The cursor for the previous page, uses the 'created_at' field"
        ),
    ] = None
    limit: Annotated[int, Field(gt=0, description="The number of items per page")]


class PaginatedProductsResponse(PaginatedResponse[ProductWithoutUser]):
    vendor: User
