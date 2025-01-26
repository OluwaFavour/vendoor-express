from typing import Annotated
from uuid import UUID

import aiosmtplib
from fastapi import Request, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
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


async def get_async_smtp():
    """
    Asynchronous generator to get an SMTP client for sending emails.

    This function initializes an asynchronous SMTP client using the settings
    retrieved from the application configuration. It attempts to connect to the
    SMTP server, start TLS, and authenticate using the provided credentials.
    If any step fails, an appropriate HTTPException is raised.

    Yields:
        aiosmtplib.SMTP: An authenticated and connected SMTP client.

    Raises:
        HTTPException: If there is an error connecting to the SMTP server, starting TLS,
                       authenticating, or any other SMTP-related error.
    """
    SETTINGS = get_settings()
    async_smtp = aiosmtplib.SMTP(
        hostname=SETTINGS.smtp_host,
        port=SETTINGS.smtp_port,
        use_tls=False,
        start_tls=False,
    )
    try:
        await async_smtp.connect()
        await async_smtp.starttls()
        await async_smtp.login(SETTINGS.smtp_login, SETTINGS.smtp_password)
        yield async_smtp
    except aiosmtplib.SMTPConnectError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Could not connect to SMTP server", "error": str(e)},
        )
    except aiosmtplib.SMTPHeloError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Could not start TLS", "error": str(e)},
        )
    except aiosmtplib.SMTPAuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Could not authenticate", "error": str(e)},
        )
    except aiosmtplib.SMTPException as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "An error occurred", "error": str(e)},
        )
    finally:
        try:
            await async_smtp.quit()
        except aiosmtplib.SMTPResponseException as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={"message": "An error occurred", "error": str(e)},
            )
