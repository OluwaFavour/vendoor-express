from typing import Annotated
from uuid import UUID

from fastapi import Request, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.config import get_async_session
from app.db.models import User


async def get_logged_in_user(
    request: Request, session: Annotated[AsyncSession, Depends(get_async_session)]
) -> User | None:
    """
    get_logged_in_user retrieves the logged in user from the session.

    Args:
        request (Request): The request object.
        session (AsyncSession): The SQLAlchemy AsyncSession.

    Returns:
        User | None: The logged in user, or None if not found.
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return None

    try:
        # Ensure user_id is a valid UUID
        user_uuid = UUID(user_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid session user ID",
        )

    try:
        user = await User.get(session, id=user_uuid)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    return user


async def get_logged_in_active_user(
    request: Request, session: Annotated[AsyncSession, Depends(get_async_session)]
) -> User | None:
    """
    get_logged_in_active_user retrieves the logged in active user from the session.

    Args:
        request (Request): The request object.
        session (AsyncSession): The SQLAlchemy AsyncSession.

    Returns:
        User | None: The logged in active user, or None if not found.
    """
    user = await get_logged_in_user(request, session)
    if user and user.is_active and not user.is_deleted:
        return user
    return None
