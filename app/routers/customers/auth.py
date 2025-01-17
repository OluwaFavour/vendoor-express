from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Form, Request, status, HTTPException

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.config import get_async_session
from app.db.models import Customer
from app.core.dependencies import get_logged_in_active_customer
from app.schemas.customers import (
    LoginDetails,
    Customer as CustomerSchema,
    CustomerCreate,
    PasswordChangeData,
)


router = APIRouter(
    prefix="/customers/auth",
    tags=["customers", "auth"],
)


@router.post("/login", status_code=status.HTTP_200_OK)
async def login_customer(
    data: Annotated[LoginDetails, Form()],
    request: Request,
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> CustomerSchema:
    """
    login_customer logs in a customer using the provided login details.

    Args:
        data (LoginDetails): The login details of the customer.
        request (Request): The request object.
        session (AsyncSession): The SQLAlchemy AsyncSession.

    Returns:
        CustomerSchema: The logged in customer.
    """

    try:
        customer = await Customer.get(session, email=data.email)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    if not customer:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found"
        )

    if not await customer.authenticate(data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password"
        )

    if not customer.is_active or customer.is_deleted:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Customer is inactive or deleted",
        )

    # Add customer_id to the session
    request.session.update({"customer_id": str(customer.id)})

    return customer


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_200_OK: {
            "description": "Successfully logged out",
            "content": {
                "application/json": {"example": {"message": "Successfully logged out"}}
            },
        }
    },
)
async def logout_customer(request: Request):
    """
    logout_customer logs out a customer by removing the customer_id from the session.

    Args:
        request (Request): The request object.

    Returns:
        dict: The response message.
    """
    request.session.pop("customer_id", None)
    return {"message": "Successfully logged out"}


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register_customer(
    data: Annotated[CustomerCreate, Form()],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> CustomerSchema:
    """
    register_customer registers a new customer.

    Args:
        data (CustomerCreate): The data to create the customer with.
        session (AsyncSession): The SQLAlchemy AsyncSession.

    Returns:
        CustomerSchema: The created customer.
    """
    try:
        customer = await Customer.create(session, **data.model_dump())
        return customer
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e)
        )


@router.post("/change_password", status_code=status.HTTP_200_OK)
async def change_password(
    data: Annotated[PasswordChangeData, Form()],
    customer: Annotated[Customer | None, Depends(get_logged_in_active_customer)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> CustomerSchema:
    """
    change_password changes the password of the logged in customer.

    Args:
        data (PasswordChangeData): The data to change the password with.
        customer (Customer): The logged in customer.
        session (AsyncSession): The SQLAlchemy AsyncSession.

    Returns:
        CustomerSchema: The updated customer.
    """
    if not customer:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Customer not logged in"
        )

    if not await customer.authenticate(data.old_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password"
        )

    customer = await customer.change_password(session, data.new_password)
    return customer
