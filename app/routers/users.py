from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request, status, HTTPException

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.config import get_async_session
from app.db.models import User
from app.core.dependencies import get_logged_in_active_user
from app.schemas.users import (
    LoginDetails,
    User as UserSchema,
    UserCreate,
    PasswordChangeData,
)


router = APIRouter(
    prefix="/users/auth",
    tags=["users", "auth"],
)


@router.post("/login", status_code=status.HTTP_200_OK)
async def login(
    data: Annotated[LoginDetails, Form()],
    request: Request,
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> UserSchema:
    """
    login logs in a user using the provided login details.

    Args:
        data (LoginDetails): The login details of the user.
        request (Request): The request object.
        session (AsyncSession): The SQLAlchemy AsyncSession.

    Returns:
        UserSchema: The logged in user.
    """

    try:
        user = await User.get(session, email=data.email)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    if not await user.authenticate(data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password"
        )

    if not user.is_active or user.is_deleted:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is inactive or deleted",
        )

    # Add user_id to the session
    request.session.update({"user_id": str(user.id)})

    return user


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
async def logout(request: Request):
    """
    logout logs out a user by removing the user_id from the session.

    Args:
        request (Request): The request object.

    Returns:
        dict: The response message.
    """
    request.session.pop("user_id", None)
    return {"message": "Successfully logged out"}


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    data: Annotated[UserCreate, Form()],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> UserSchema:
    """
    register registers a new user.

    Args:
        data (UserCreate): The data to create the user with.
        session (AsyncSession): The SQLAlchemy AsyncSession.

    Returns:
        UserSchema: The created user.
    """
    try:
        user = await User.create(session, **data.model_dump())
        return user
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e)
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

    if not await user.authenticate(data.old_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password"
        )

    user = await user.change_password(session, data.new_password)
    return user
