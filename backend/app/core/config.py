import os
from typing import Any, Dict, Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # App Settings
    APP_NAME: str = "ThreatWatch-AI"
    APP_ENV: str = "development"
    DEBUG: bool = True
    SECRET_KEY: str = "generate-a-secure-secret-key-for-production"

    # Database Settings
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    POSTGRES_DB: str = "threatwatch_ai"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    
    DATABASE_URL: Optional[str] = None

    # SMTP Mail Settings
    EMAIL_HOST: str = "smtp.gmail.com"
    EMAIL_PORT: int = 587
    EMAIL_USERNAME: Optional[str] = None
    EMAIL_PASSWORD: Optional[str] = None
    EMAIL_RECEIVER: Optional[str] = None

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def assemble_db_connection(cls, v: Optional[str], info: Any) -> Any:
        if isinstance(v, str) and v:
            # Fix standard cloud database URLs using postgres:// to postgresql://
            if v.startswith("postgres://"):
                return v.replace("postgres://", "postgresql://", 1)
            return v
        
        # Fallback to assembling from individual components if DATABASE_URL is missing
        data = info.data
        user = data.get("POSTGRES_USER")
        password = data.get("POSTGRES_PASSWORD")
        host = data.get("POSTGRES_HOST")
        port = data.get("POSTGRES_PORT")
        db = data.get("POSTGRES_DB")
        
        return f"postgresql://{user}:{password}@{host}:{port}/{db}"

    model_config = SettingsConfigDict(
        env_file=os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".env"),
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )


settings = Settings()
