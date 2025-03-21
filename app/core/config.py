import cloudinary

from passlib.context import CryptContext

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.logger import setup_logger


class Settings(BaseSettings):

    # App Settings
    app_name: str = "Vendoor Express API"
    app_url: str = "https://d81a-102-89-75-80.ngrok-free.app/api/v1"
    app_version: str = "0.0.1"
    debug: bool = True

    # CORS Settings
    cors_allow_credentials: bool = True
    cors_allowed_methods: list[str] = ["*"]
    cors_allowed_origins: list[str] = ["*"]

    # Cloudinary Settings
    cloudinary_cloud_name: str
    cloudinary_api_key: str
    cloudinary_api_secret: str

    # Database Settings
    database_url: str = "sqlite:///./test.db"

    # Email Settings
    from_email: str
    from_name: str = "Vendoor Express"

    # JWT Settings
    jwt_algorithm: str = "HS256"
    jwt_expiry_minutes: int = 60
    otp_expiry_minutes: int = 5

    # Login Settings
    short_login_expiry_minutes: int = 60
    long_login_expiry_days: int = 7

    # Session Settings
    session_expire_days: int = 7
    session_same_site: str = "lax"
    session_secret_key: str
    session_secure: bool = False

    # SMTP Settings
    smtp_host: str
    smtp_login: str
    smtp_password: str
    smtp_port: int

    model_config = SettingsConfigDict(env_file=".env")


@lru_cache
def get_settings():
    return Settings()


# Database logger instance
db_logger = setup_logger("database_logger", "logs/database_actions.log")

# Request logger instance
request_logger = setup_logger("request_logger", "logs/request_actions.log")

# Password hashing context
password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Cloudinary configuration
cloudinary.config(
    cloud_name=get_settings().cloudinary_cloud_name,
    api_key=get_settings().cloudinary_api_key,
    api_secret=get_settings().cloudinary_api_secret,
    secure=True,
)
