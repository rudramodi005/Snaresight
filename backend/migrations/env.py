"""Alembic environment configuration for SnareSight schema migrations."""

import os
import sys
from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context

# Prepend backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.config import settings
from app.db.base import Base

# Import all SQLAlchemy models to register them on Base.metadata
import app.db.models  # noqa: F401

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_url():
    """Retrieves authoritative database URL from application settings."""
    url = os.getenv("DATABASE_URL", str(settings.DATABASE_URL))
    if url.startswith("sqlite"):
        return url
    # Convert postgresql+asyncpg to psycopg2 / postgresql for synchronous Alembic runner
    if url.startswith("postgresql+asyncpg://"):
        return url.replace("postgresql+asyncpg://", "postgresql://")
    if url.startswith("postgresql+psycopg://"):
        try:
            import psycopg  # noqa: F401
        except ImportError:
            return url.replace("postgresql+psycopg://", "postgresql+psycopg2://")
    return url


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = get_url()

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

