from datetime import datetime

from typing import Annotated, Any, Self
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
    model_validator,
)

from app.core.validators import validate_phone, validate_password


class CustomerBase(BaseModel):
    email: Annotated[EmailStr, Field(..., title="Email address")]
    first_name: str
    last_name: str
    phone: Annotated[
        str,
        Field(
            title="Phone number",
            description="Phone number in international format, e.g. +2348123456789",
        ),
    ]

    @field_validator("phone")
    def phone_validator(cls, value: str) -> str:
        """
        phone_validator validates the phone number using the phonenumbers library.

        Args:
            value (str): The phone number to validate

        Returns:
            str: The validated phone number
        """
        return validate_phone(value)


class CustomerCreate(CustomerBase):
    password: Annotated[
        str,
        Field(
            ...,
            min_length=8,
            description="Password for the customer account, must be at least 8 characters long, contain at least one digit, one uppercase letter, one lowercase letter, and one special character, and not contain spaces.",
        ),
    ]
    model_config: ConfigDict = ConfigDict(extra="forbid")

    @field_validator("password")
    def password_validator(cls, value: str) -> str:
        """
        password_validator validates the password.

        Args:
            value (str): The password to validate

        Returns:
            str: The validated password
        """
        return validate_password(value)


class Customer(CustomerBase):
    model_config: ConfigDict = ConfigDict(from_attributes=True)
    id: UUID
    is_active: bool
    is_deleted: bool
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="before")
    @classmethod
    def convert_id_to_string(cls, data: Any) -> Any:
        """
        Convert UUID 'id' fields to string in a given data structure.

        This method checks if the input data is a dictionary or an object with an 'id' attribute.
        If the 'id' is of type UUID, it converts it to a string.

        Args:
            data (Any): The input data which can be a dictionary or an object.

        Returns:
            Any: The modified data with 'id' fields converted to strings if they were UUIDs.
        """
        if isinstance(data, dict):
            if isinstance(data.get("id"), UUID):
                data["id"] = str(data["id"])
        elif hasattr(data, "id") and isinstance(data.id, UUID):
            data.id = str(data.id)
        return data


class LoginDetails(BaseModel):
    email: EmailStr
    password: str
    model_config: ConfigDict = ConfigDict(extra="forbid")


class PasswordChangeData(BaseModel):
    old_password: str
    new_password: str
    model_config: ConfigDict = ConfigDict(extra="forbid")

    @field_validator("new_password")
    def new_password_validator(cls, value: str):
        """
        new_password_validator validates the new password.

        Args:
            value (str): The new password to validate

        Returns:
            str: The validated new password
        """
        return validate_password(value)

    @model_validator(mode="after")
    def password_change_validator(self) -> Self:
        if self.old_password == self.new_password:
            raise ValueError("New password must be different from old password")
        return self
