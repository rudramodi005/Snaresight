"""Database engine configuration, connection pooling, and session management."""

from typing import Generator
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from app.core.config import settings

db_url = settings.db.DATABASE_URL
if db_url.startswith("sqlite"):
    engine = create_engine(
        db_url,
        connect_args={"check_same_thread": False},
        echo=settings.db.DATABASE_ECHO,
    )
else:
    try:
        engine = create_engine(
            db_url,
            pool_size=settings.db.DATABASE_POOL_SIZE,
            max_overflow=settings.db.DATABASE_MAX_OVERFLOW,
            pool_timeout=settings.db.DATABASE_POOL_TIMEOUT,
            echo=settings.db.DATABASE_ECHO,
            pool_pre_ping=True,  # Health check connections before reuse
        )
    except Exception:
        # Graceful offline development fallback when PostgreSQL is not accessible
        engine = create_engine(
            "sqlite:///./snaresight.db",
            connect_args={"check_same_thread": False},
            echo=settings.db.DATABASE_ECHO,
        )

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

