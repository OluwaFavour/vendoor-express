import secrets
from app.core.config import password_context


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
