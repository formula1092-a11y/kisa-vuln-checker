"""Application configuration."""
import os
from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings."""

    # Application
    APP_NAME: str = "KISA Vulnerability Checker"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Database
    DATABASE_URL: str = "sqlite:///./kisa_vuln.db"

    # Authentication
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "admin123!"  # Change in production
    SECRET_KEY: str = "change-this-secret-key-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    # File Upload
    STORAGE_PATH: Path = Path("./storage")
    MAX_UPLOAD_SIZE: int = 10 * 1024 * 1024  # 10MB
    ALLOWED_EXTENSIONS: set = {
        ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".txt",
        ".doc", ".docx", ".xls", ".xlsx", ".csv", ".zip"
    }

    class Config:
        env_file = ".env"
        extra = "allow"


settings = Settings()

# Ensure storage directory exists
settings.STORAGE_PATH.mkdir(parents=True, exist_ok=True)
