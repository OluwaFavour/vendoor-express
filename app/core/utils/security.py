from datetime import datetime, timedelta
import jwt
import secrets
from typing import Any

from app.core.config import password_context, get_settings


SETTINGS = get_settings()


def hash_password(password: str) -> str:
    """
    Hashes a plain text password using a password hashing context.

    Args:
        password (str): The plain text password to be hashed.

    Returns:
        str: The hashed password.
    """
    return password_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify if the provided plain password matches the hashed password.

    Args:
        plain_password (str): The plain text password to verify.
        hashed_password (str): The hashed password to compare against.

    Returns:
        bool: True if the plain password matches the hashed password, False otherwise.
    """
    return password_context.verify(plain_password, hashed_password)


def generate_otp() -> str:
    """
    Generate a 6-character OTP (One-Time Password) consisting of
    uppercase letters and digits.

    Returns:
        str: A randomly generated 6-character OTP.
    """
    return "".join(
        secrets.choice("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(6)
    )


def encode(data: dict[str, Any], expiry_time: timedelta) -> str:
    """
    Encode data using JWT.

    Args:
        data (dict[str, Any]): The data to encode.
        expiry_time (timedelta): The expiry time for the token.

    Returns:
        str: The encoded JWT token.
    """
    expiration = datetime.now() + expiry_time
    data.update({"exp": expiration})
    return jwt.encode(
        data, SETTINGS.session_secret_key, algorithm=SETTINGS.jwt_algorithm
    )


def decode(token: str) -> dict[str, Any]:
    """
    Decode a JWT token.

    Args:
        token (str): The JWT token to decode.

    Returns:
        dict[str, Any]: The decoded data.
    """
    try:
        return jwt.decode(
            token, SETTINGS.session_secret_key, algorithms=[SETTINGS.jwt_algorithm]
        )
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")
