"""SQLAlchemy 2.0 Declarative Base with strict constraint naming conventions."""

from sqlalchemy import MetaData, JSON, Uuid
from sqlalchemy.dialects.postgresql import JSONB as PG_JSONB, UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase

# Constraint naming conventions for PostgreSQL
POSTGRES_NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

# Cross-dialect JSONB and UUID compatibility types (native on PostgreSQL, JSON/UUID on SQLite)
JSONB_TYPE = JSON().with_variant(PG_JSONB(), "postgresql")
UUID_TYPE = Uuid(as_uuid=True).with_variant(PG_UUID(as_uuid=True), "postgresql")


class Base(DeclarativeBase):
    """Abstract declarative base for all SnareSight relational entities."""
    
    metadata = MetaData(naming_convention=POSTGRES_NAMING_CONVENTION)


