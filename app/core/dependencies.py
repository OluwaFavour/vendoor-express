from typing import Annotated
from uuid import UUID

from fastapi import Request, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.config import get_async_session
from app.db.models import Customer


async def get_logged_in_customer(
    request: Request, session: Annotated[AsyncSession, Depends(get_async_session)]
) -> Customer | None:
    """
    get_logged_in_customer retrieves the logged in customer from the session.

    Args:
        request (Request): The request object.
        session (AsyncSession): The SQLAlchemy AsyncSession.

    Returns:
        Customer | None: The logged in customer, or None if not found.
    """
    customer_id = request.session.get("customer_id")
    if not customer_id:
        return None

    try:
        # Ensure customer_id is a valid UUID
        customer_uuid = UUID(customer_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid session customer ID",
        )

    try:
        customer = await Customer.get(session, id=customer_uuid)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    return customer


async def get_logged_in_active_customer(
    request: Request, session: Annotated[AsyncSession, Depends(get_async_session)]
) -> Customer | None:
    """
    get_logged_in_active_customer retrieves the logged in active customer from the session.

    Args:
        request (Request): The request object.
        session (AsyncSession): The SQLAlchemy AsyncSession.

    Returns:
        Customer | None: The logged in active customer, or None if not found.
    """
    customer = await get_logged_in_customer(request, session)
    if customer and customer.is_active and not customer.is_deleted:
        return customer
    return None
