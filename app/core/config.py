from passlib.context import CryptContext

from functools import lru_cache
from pydantic_settings import BaseSettings

from app.core.logger import setup_logger


class Settings(BaseSettings):
    allow_credentials: bool = True
    allowed_methods: list[str] = ["*"]
    allowed_origins: list[str] = ["*"]
    app_name: str = "Find-a-Home_FUTA API"
    app_version: str = "0.0.1"
    database_url: str = "sqlite:///./test.db"
    debug: bool = True
    # from_email: str
    # from_name: str
    # otp_expiry_minutes: int = 5
    session_expire_days: int = 7
    session_same_site: str = "lax"
    session_secret_key: str
    session_secure: bool = False
    # smtp_host: str
    # smtp_login: str
    # smtp_password: str
    # smtp_port: int

    class Config:
        env_file = ".env"


@lru_cache
def get_settings():
    return Settings()


# Database logger instance
db_logger = setup_logger("database_logger", "logs/database_actions.log")

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
