"""SnareSight backend core configuration module.

Loads application, database, and security settings from environment variables.
"""

import os
from typing import Optional
from pydantic import BaseModel, Field


class DatabaseSettings(BaseModel):
    """PostgreSQL connection and pooling configuration."""
    
    DATABASE_URL: str = Field(
        default_factory=lambda: os.getenv(
            "DATABASE_URL",
            "postgresql+psycopg://snaresight_app:local_dev_password@127.0.0.1:5432/snaresight"
        ),
        description="Async/Sync SQLAlchemy database connection URL"
    )
    MIGRATION_DATABASE_URL: str = Field(
        default_factory=lambda: os.getenv(
            "MIGRATION_DATABASE_URL",
            "postgresql+psycopg://snaresight_migrator:local_dev_password@127.0.0.1:5432/snaresight"
        ),
        description="Database URL for Alembic migration executions"
    )
    DATABASE_POOL_SIZE: int = Field(
        default_factory=lambda: int(os.getenv("DATABASE_POOL_SIZE", "5")),
        ge=1,
        le=20,
        description="SQLAlchemy connection pool size"
    )
    DATABASE_MAX_OVERFLOW: int = Field(
        default_factory=lambda: int(os.getenv("DATABASE_MAX_OVERFLOW", "10")),
        ge=0,
        le=30
    )
    DATABASE_POOL_TIMEOUT: int = Field(
        default_factory=lambda: int(os.getenv("DATABASE_POOL_TIMEOUT", "30")),
        ge=1,
        le=120
    )
    DATABASE_ECHO: bool = Field(
        default_factory=lambda: os.getenv("DATABASE_ECHO", "false").lower() == "true",
        description="Enable SQLAlchemy SQL query logging"
    )


class AppSettings(BaseModel):
    """Top-level backend settings."""
    
    PROJECT_NAME: str = "SnareSight"
    ENVIRONMENT: str = Field(default_factory=lambda: os.getenv("ENVIRONMENT", "development"))
    API_PREFIX: str = "/api/v1"
    SECRET_KEY: str = Field(default_factory=lambda: os.getenv("SECRET_KEY", "insecure-dev-key-change-in-prod"))
    JWT_SECRET_KEY: str = Field(default_factory=lambda: os.getenv("JWT_SECRET_KEY", os.getenv("SECRET_KEY", "insecure-dev-key-change-in-prod")))
    JWT_ALGORITHM: str = Field(default_factory=lambda: os.getenv("JWT_ALGORITHM", "HS256"))
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default_factory=lambda: int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60")))
    AUTH_ENFORCEMENT_MODE: str = Field(default_factory=lambda: os.getenv("AUTH_ENFORCEMENT_MODE", "PERMISSIVE_DEV"))
    RATE_LIMIT_LOGIN_MAX_ATTEMPTS: int = Field(default_factory=lambda: int(os.getenv("RATE_LIMIT_LOGIN_MAX_ATTEMPTS", "5")))
    RATE_LIMIT_LOGIN_WINDOW_MINUTES: int = Field(default_factory=lambda: int(os.getenv("RATE_LIMIT_LOGIN_WINDOW_MINUTES", "15")))
    MAX_REQUEST_BODY_SIZE_BYTES: int = Field(default_factory=lambda: int(os.getenv("MAX_REQUEST_BODY_SIZE_BYTES", "2097152")))
    db: DatabaseSettings = Field(default_factory=DatabaseSettings)

    @property
    def DATABASE_URL(self) -> str:
        return self.db.DATABASE_URL


settings = AppSettings()

