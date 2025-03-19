import re

import phonenumbers


def validate_phone(phone: str) -> str:
    """
    validate_phone validates the phone number using the phonenumbers library.

    Args:
        phone (str): The phone number to validate

    Returns:
        str: The validated phone number

    Raises:
        ValueError: If the phone number is invalid
    """
    try:
        parsed_phone = phonenumbers.parse(
            phone, "NG"
        )  # Parse the phone number for Nigeria
        if not phonenumbers.is_valid_number(parsed_phone):
            raise ValueError("Invalid phone number")
    except phonenumbers.phonenumberutil.NumberParseException:
        raise ValueError("Invalid phone number")
    else:
        return phone


def validate_password(password: str) -> str:
    """
    validate_password validates the password.

    Args:
        password (str): The password to validate

    Returns:
        str: The validated password

    Raises:
        ValueError: If the password is invalid
    """
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")

    # Check for at least one digit
    if not any(char.isdigit() for char in password):
        raise ValueError("Password must contain at least one digit")

    # Check for at least one uppercase letter
    if not any(char.isupper() for char in password):
        raise ValueError("Password must contain at least one uppercase letter")

    # Check for at least one lowercase letter
    if not any(char.islower() for char in password):
        raise ValueError("Password must contain at least one lowercase letter")

    # Check for at least one special character using regex
    if not re.search(r'[!@#$%^&*(),.?":;{}|<>\\/-_+=`~]', password):
        raise ValueError("Password must contain at least one special character")

    # Check for spaces
    if " " in password:
        raise ValueError("Password must not contain spaces")

    return password
