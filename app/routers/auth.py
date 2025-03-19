from datetime import timedelta
from aiosmtplib import SMTP
from typing import Annotated

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    Form,
    Request,
    status,
    HTTPException,
)

import jwt
from pydantic import EmailStr
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings, request_logger
from app.core.utils.messages import send_email
from app.core.utils.security import decode, encode
from app.db.config import get_async_session
from app.db.models import User, OTP
from app.core.dependencies import get_async_smtp, get_logged_in_active_user
from app.schemas.users import (
    LoginDetails,
    Message,
    Output,
    User as UserSchema,
    UserCreate,
    PasswordChangeData,
    VerificationData,
)


router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)


async def send_verification_email(otp: OTP, user: User) -> None:
    """
    Sends a verification email to the user.

    Args:
        otp (OTP): The OTP object.
        user (User): The user object.
    """
    settings = get_settings()

    # Send email
    async with get_async_smtp() as smtp:
        try:
            message = f"Your verification code is: {otp.code}, valid for {settings.otp_expiry_minutes} minutes."
            await send_email(
                smtp=smtp,
                subject="Email Verification",
                recipient={"email": user.email, "display_name": user.full_name},
                plain_text=message,
                sender=settings.smtp_login,
            )
            request_logger.info(f"Verification email sent to {user.email}")
        except Exception as e:
            request_logger.error(
                f"Error sending verification email to {user.email}: {e}"
            )


@router.post("/login", status_code=status.HTTP_200_OK)
async def login(
    data: Annotated[LoginDetails, Form()],
    request: Request,
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> Output:
    """
    login logs in a user using the provided login details.

    Args:
        data (LoginDetails): The login details of the user.
        request (Request): The request object.
        session (AsyncSession): The SQLAlchemy AsyncSession.

    Returns:
        Output: The response message and user object.
    """

    try:
        user = await User.get(session, email=data.email)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    if not user.authenticate(data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password"
        )

    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is unverified",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is inactive",
        )
    if user.is_deleted:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="User is deleted"
        )

    # Encode user_id and add to the session
    session_token = None
    if data.remember_me:
        session_token = encode(
            {"sub": str(user.id)},
            timedelta(days=get_settings().long_login_expiry_days),
        )
    else:
        session_token = encode(
            {"sub": str(user.id)},
            timedelta(minutes=get_settings().short_login_expiry_minutes),
        )
    request.session.update({"session_token": session_token})

    return Output(message="Successfully logged in", user=user)


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
async def logout(
    request: Request, user: Annotated[User, Depends(get_logged_in_active_user)]
) -> Message:
    """
    logout logs out a user by removing the user_id from the session.

    Args:
        request (Request): The request object.

    Returns:
        dict: The response message.
    """
    session_token = request.session.get("session_token")
    if not session_token:
        request_logger.warning(
            f"Logout attempted with no session token for user {user.id}"
        )
        # Already logged out, so proceed with success
        return Message(message="Successfully logged out")

    try:
        payload = decode(session_token)
        token_user_id: str = payload.get("sub")  #
        if token_user_id != str(user.id):
            request_logger.warning(
                f"Token user_id {token_user_id} does not match user {user.id}"
            )
            raise HTTPException(
                status_code=401,
                detail="Current user does not match session token owner",
            )
    except jwt.ExpiredSignatureError:
        request_logger.warning(
            f"Expired session token during logout for user {user.id}"
        )
        # Expired token is fine for logout, proceed
    except jwt.InvalidTokenError:
        request_logger.warning(
            f"Invalid session token during logout for user {user.id}"
        )
        raise HTTPException(status_code=401, detail="Invalid session token")

    request.session.pop("session_token", None)
    request_logger.info(f"User {user.id} successfully logged out")
    return Message(message="Successfully logged out")


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    data: Annotated[UserCreate, Form()],
    session: Annotated[AsyncSession, Depends(get_async_session)],
    background_tasks: BackgroundTasks,
) -> Output:
    """
    register sends an OTP to the user's email.

    Args:
        data (UserCreate): The user data.
        session (AsyncSession): The SQLAlchemy AsyncSession.
        background_tasks (BackgroundTasks): The FastAPI background tasks.

    Returns:
        Output: The response message and user object.
    """
    try:
        async with session.begin():
            user = await User.create(session, commit_self=False, **data.model_dump())
            # Create OTP
            otp = await OTP.create(session, user_id=user.id, commit_self=False)

        # Send OTP to user's email
        background_tasks.add_task(send_verification_email, otp, user)
        return {
            "message": f"Verification email sent, check your email. The OTP is only valid for {get_settings().otp_expiry_minutes} minutes.",
            "user": user,
        }
    except ValueError as e:
        request_logger.warning(f"Registration failed for {data.email}: {str(e)}")
        raise HTTPException(status_code=422, detail=str(e))
    except IntegrityError as e:
        request_logger.warning(f"Registration conflict for {data.email}: {str(e)}")
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        request_logger.error(
            f"Unexpected error during registration for {data.email}: {str(e)}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )


@router.post("/resend_otp", status_code=status.HTTP_200_OK)
async def resend_otp(
    email: Annotated[EmailStr, Form()],
    session: Annotated[AsyncSession, Depends(get_async_session)],
    background_tasks: BackgroundTasks,
) -> Output:
    """
    resend_otp resends the OTP to the user's email.

    Args:
        email (EmailStr): The email of the user.
        session (AsyncSession): The SQLAlchemy AsyncSession.

    Returns:
        Output: The response message and user object.
    """
    try:
        async with session.begin():
            user = await User.get(session, email=email)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
                )
            if user.is_verified:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User is already verified",
                )
            otp = await OTP.get(session, user_id=user.id)
            if otp and not otp.is_valid:
                session.delete(otp)

            # Create a new OTP if none exists, or regenerate the existing one
            if not otp:
                otp = await OTP.create(session, user_id=user.id, commit_self=False)
            else:
                try:
                    await otp.regenerate(session, commit_self=False)
                except Exception as e:
                    request_logger.error(
                        f"Failed to regenerate OTP for {email}: {str(e)}"
                    )
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail=f"Internal server error: {str(e)}",
                    )
        # Send OTP to user's email using background task
        background_tasks.add_task(send_verification_email, otp, user)
        return Output(
            message=f"Verification email sent, check your email. The OTP is only valid for {get_settings().otp_expiry_minutes} minutes.",
            user=user,
        )
    except HTTPException:
        raise
    except Exception as e:
        request_logger.error(f"Failed to resend OTP for {email}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )


@router.post("/verify", status_code=status.HTTP_200_OK)
async def verify_register_otp(
    data: Annotated[VerificationData, Form()],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> Output:
    """
    verify_register_otp verifies the user using the provided OTP.

    Args:
        data (VerificationData): The verification data.
        session (AsyncSession): The SQLAlchemy AsyncSession.

    Returns:
        Output: The response message and user object.
    """
    try:
        # Use the OTP
        async with session.begin():
            user = await User.get(session, email=data.email)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
                )
            otp = await OTP.get(session, user_id=user.id, code=data.code)
            if not otp:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Invalid OTP"
                )
            if not otp.is_valid:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="OTP expired, or already used",
                )
            await otp.use(
                session,
                commit_self=False,
            )  # Verifies the User and updates the otp `is_used` field to True
            request_logger.info(f"User {user.email} verified with OTP {otp.code}")
        return Output(message="User verified", user=user)
    except HTTPException:
        raise
    except ValueError as e:  # From otp.use if user is already verified
        request_logger.warning(f"Verification failed for {data.email}: {str(e)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        request_logger.error(f"Verification failed for {data.email}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}",
        )


@router.post("/change_password", status_code=status.HTTP_200_OK)
async def change_password(
    data: Annotated[PasswordChangeData, Form()],
    user: Annotated[User | None, Depends(get_logged_in_active_user)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> UserSchema:
    """
    change_password changes the password of the logged in user.

    Args:
        data (PasswordChangeData): The data to change the password with.
        user (User): The logged in user.
        session (AsyncSession): The SQLAlchemy AsyncSession.

    Returns:
        UserSchema: The updated user.
    """
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not logged in"
        )

    if not user.authenticate(data.old_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password"
        )

    user = await user.change_password(session, data.new_password)
    return user
