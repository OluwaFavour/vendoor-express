from datetime import datetime
from decimal import Decimal
from typing import Annotated
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field
from app.core.enums import DeliveryStatus
from app.schemas.users import User
from app.schemas.vendors.products import Product


class OrderArtifact(BaseModel):
    model_config: ConfigDict = ConfigDict(from_attributes=True)
    id: UUID
    order_id: UUID
    product_id: UUID
    unit: int
    price: Annotated[Decimal, Field(gt=0, decimal_places=2)]
    delivery_status: DeliveryStatus
    created_at: datetime

    product: Product


class Order(BaseModel):
    model_config: ConfigDict = ConfigDict(from_attributes=True)
    id: UUID
    user_id: UUID
    total_price: Annotated[Decimal | None, Field(gt=0, decimal_places=2)] = None
    created_at: datetime
    user: User
    artifacts: list[OrderArtifact]
