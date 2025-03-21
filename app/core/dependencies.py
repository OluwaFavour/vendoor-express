from contextlib import asynccontextmanager
from typing import Annotated
from uuid import UUID

import aiosmtplib
from fastapi import Request, Depends, HTTPException, status
import jwt
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings, request_logger
from app.core.enums import Role
from app.core.utils.security import decode
from app.db.config import get_async_session
from app.db.models import User


async def get_logged_in_user(
    request: Request, session: Annotated[AsyncSession, Depends(get_async_session)]
) -> User:
    """
    get_logged_in_user retrieves the logged in user from the session.

    Args:
        request (Request): The request object.
        session (AsyncSession): The SQLAlchemy AsyncSession.

    Returns:
        User: The logged in user

    Raises:
        HTTPException: If token is missing (401), expired/invalid (401), user_id invalid (400), or user not found/deleted (404/403).
    """
    session_token = request.session.get("session_token")
    if not session_token:
        request_logger.warning("No session token found in request")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Session token not found"
        )
    try:
        user_id: str = decode(session_token)["sub"]
    except jwt.ExpiredSignatureError:
        request_logger.warning("Session token expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session token has expired, please log in again",
        )
    except jwt.InvalidTokenError:
        request_logger.warning(f"Invalid session token: {session_token}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid session token, please log in again",
        )
    except (KeyError, ValueError):
        request_logger.warning(f"Invalid user_id in token: {session_token}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user ID in session token, please log in again",
        )

    try:
        # Ensure user_id is a valid UUID
        user_uuid = UUID(user_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user ID in session token, please log in again",
        )

    try:
        async with session.begin():
            user = await User.get(session, id=user_uuid)
            if not user:
                request_logger.warning(f"User not found for ID: {user_uuid}")
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
                )
            if user.is_deleted:
                request_logger.warning(f"User deleted: {user_uuid}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="User is deleted"
                )
        return user
    except HTTPException:
        raise
    except Exception as e:
        request_logger.error(
            f"Failed to retrieve user {user_uuid}: {str(e)}", exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}",
        )


async def get_logged_in_active_user(
    user: Annotated[User, Depends(get_logged_in_user)],
) -> User:
    """
    get_logged_in_active_user retrieves the logged in active user from the session.

    Args:
        user (User): The user object from get_logged_in_user.

    Returns:
        User: The logged in active user.

    Raises:
        HTTPException: If user is not active (403) or not verified (403).
    """
    if not user.is_active:
        request_logger.warning(f"User {user.id} is not active")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="User is not active"
        )
    if not user.is_verified:
        request_logger.warning(f"User {user.id} is not verified")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="User is not verified"
        )
    return user


async def get_logged_in_vendor(
    user: Annotated[User, Depends(get_logged_in_active_user)],
) -> User:
    """
    get_logged_in_vendor retrieves the logged in vendor from the session.

    Args:
        user (User): The user object from get_logged_in_active_user.

    Returns:
        User: The logged in vendor.

    Raises:
        HTTPException: If user is not a vendor (403).
    """
    if user.role != Role.VENDOR:
        request_logger.warning(f"User {user.id} is not a vendor")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="User is not a vendor"
        )
    return user


async def get_logged_in_admin(
    user: Annotated[User, Depends(get_logged_in_active_user)],
) -> User:
    """
    get_logged_in_admin retrieves the logged in admin from the session.

    Args:
        user (User): The user object from get_logged_in_active_user.

    Returns:
        User: The logged in admin.

    Raises:
        HTTPException: If user is not an admin (403).
    """
    if user.role != Role.ADMIN:
        request_logger.warning(f"User {user.id} is not an admin")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="User is not an admin"
        )
    return user


async def get_logged_in_customer(
    user: Annotated[User, Depends(get_logged_in_active_user)],
) -> User:
    """
    get_logged_in_customer retrieves the logged in customer from the session.

    Args:
        user (User): The user object from get_logged_in_active_user.

    Returns:
        User: The logged in customer.

    Raises:
        HTTPException: If user is not a customer (403).
    """
    if user.role != Role.CUSTOMER:
        request_logger.warning(f"User {user.id} is not a customer")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="User is not a customer"
        )
    return user


@asynccontextmanager
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
        request_logger.info(
            f"Connecting to SMTP server {SETTINGS.smtp_host}:{SETTINGS.smtp_port}"
        )
        await async_smtp.connect()
        await async_smtp.starttls()
        await async_smtp.login(SETTINGS.smtp_login, SETTINGS.smtp_password)
        request_logger.info("SMTP client authenticated successfully")
        yield async_smtp
    except aiosmtplib.SMTPConnectError as e:
        request_logger.error(f"Failed to connect to SMTP server: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Could not connect to SMTP server", "error": str(e)},
        )
    except aiosmtplib.SMTPHeloError as e:
        request_logger.error(f"Failed to start TLS: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Could not start TLS", "error": str(e)},
        )
    except aiosmtplib.SMTPAuthenticationError as e:
        request_logger.error(f"SMTP authentication failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "Could not authenticate", "error": str(e)},
        )
    except aiosmtplib.SMTPException as e:
        request_logger.error(f"SMTP error occurred: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"message": "An error occurred", "error": str(e)},
        )
    finally:
        try:
            await async_smtp.quit()
            request_logger.info("SMTP client connection closed")
        except aiosmtplib.SMTPException as e:
            request_logger.error(f"Failed to close SMTP connection: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={"message": "Failed to close SMTP connection", "error": str(e)},
            )
