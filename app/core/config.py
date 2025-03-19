from passlib.context import CryptContext

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.logger import setup_logger


class Settings(BaseSettings):
    allow_credentials: bool = True
    allowed_methods: list[str] = ["*"]
    allowed_origins: list[str] = ["*"]
    app_name: str = "Vendoor Express API"
    app_version: str = "0.0.1"
    database_url: str = "sqlite:///./test.db"
    debug: bool = True
    from_email: str
    from_name: str = "Vendoor Express"
    jwt_algorithm: str = "HS256"
    jwt_expiry_minutes: int = 60
    otp_expiry_minutes: int = 5
    session_expire_days: int = 7
    session_same_site: str = "lax"
    session_secret_key: str
    session_secure: bool = False
    smtp_host: str
    smtp_login: str
    smtp_password: str
    smtp_port: int

    # Login Settings
    short_login_expiry_minutes: int = 60
    long_login_expiry_days: int = 7

    model_config = SettingsConfigDict(env_file=".env")


@lru_cache
def get_settings():
    return Settings()


# Database logger instance
db_logger = setup_logger("database_logger", "logs/database_actions.log")

# Request logger instance
request_logger = setup_logger("request_logger", "logs/request_actions.log")

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
