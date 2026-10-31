"""Database engine configuration, connection pooling, and session management."""

import logging
from typing import Generator
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from app.core.config import settings

logger = logging.getLogger("snaresight.db")


def _resolve_database_url(url: str) -> str:
    """Normalize database URL for available PostgreSQL drivers (psycopg vs psycopg2)."""
    if url.startswith("postgresql+psycopg://"):
        try:
            import psycopg  # noqa: F401
        except ImportError:
            # Fall back to psycopg2 driver if psycopg v3 is not installed
            try:
                import psycopg2  # noqa: F401
                return url.replace("postgresql+psycopg://", "postgresql+psycopg2://")
            except ImportError:
                pass
    return url


def _create_db_engine():
    """Initializes database engine with driver normalization and offline fallback."""
    raw_url = settings.db.DATABASE_URL
    if raw_url.startswith("sqlite"):
        return create_engine(
            raw_url,
            connect_args={"check_same_thread": False},
            echo=settings.db.DATABASE_ECHO,
        )

    resolved_url = _resolve_database_url(raw_url)
    try:
        return create_engine(
            resolved_url,
            pool_size=settings.db.DATABASE_POOL_SIZE,
            max_overflow=settings.db.DATABASE_MAX_OVERFLOW,
            pool_timeout=settings.db.DATABASE_POOL_TIMEOUT,
            echo=settings.db.DATABASE_ECHO,
            pool_pre_ping=True,  # Health check connections before reuse
        )
    except Exception as exc:
        logger.warning(
            "Primary database connection failed for %s (%s). Falling back to local storage.",
            resolved_url,
            exc,
        )
        return create_engine(
            "sqlite:///./snaresight.db",
            connect_args={"check_same_thread": False},
            echo=settings.db.DATABASE_ECHO,
        )


engine = _create_db_engine()

# Session factory for synchronous queries
SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


def get_db() -> Generator[Session, None, None]:
    """Dependency generator for database sessions. Guarantees clean teardown."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_database_health() -> dict:
    """Verifies database connectivity without leaking credentials."""
    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1")).scalar()
            return {
                "status": "healthy" if result == 1 else "unhealthy",
                "database": "postgresql",
                "pool_size": settings.db.DATABASE_POOL_SIZE,
            }
    except Exception as exc:
        return {
            "status": "unhealthy",
            "database": "postgresql",
            "error": "Database connection refused or unreachable",
        }

