"""Controlled error codes and sanitized rejection diagnostics for SnareSight ingestion.

Guarantees zero disclosure of credentials, internal paths, or database connection strings.
"""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class IngestionErrorCode(str, Enum):
    """Standardized error codes for ingestion rejections."""
    
    MALFORMED_JSON = "INGEST_001_MALFORMED_JSON"
    SCHEMA_VALIDATION_FAILED = "INGEST_002_SCHEMA_VALIDATION_FAILED"
    UNSUPPORTED_SCHEMA_VERSION = "INGEST_003_UNSUPPORTED_SCHEMA_VERSION"
    UNKNOWN_SOURCE = "INGEST_004_UNKNOWN_SOURCE"
    DISABLED_SOURCE = "INGEST_005_DISABLED_SOURCE"
    UNKNOWN_DECOY = "INGEST_006_UNKNOWN_DECOY"
    SOURCE_DECOY_MISMATCH = "INGEST_007_SOURCE_DECOY_MISMATCH"
    INVALID_PROVENANCE = "INGEST_008_INVALID_PROVENANCE"
    INVALID_TIMESTAMP = "INGEST_009_INVALID_TIMESTAMP"
    FUTURE_TIMESTAMP_ANOMALY = "INGEST_010_FUTURE_TIMESTAMP_ANOMALY"
    PROHIBITED_SENSITIVE_DATA = "INGEST_011_PROHIBITED_SENSITIVE_DATA"
    DUPLICATE_EVENT = "INGEST_012_DUPLICATE_EVENT"
    OVERSIZED_BATCH = "INGEST_013_OVERSIZED_BATCH"
    OVERSIZED_FILE = "INGEST_014_OVERSIZED_FILE"
    PATH_TRAVERSAL_DETECTED = "INGEST_015_PATH_TRAVERSAL_DETECTED"
    UNAUTHORIZED_ACCESS = "INGEST_016_UNAUTHORIZED_ACCESS"
    DATABASE_TRANSACTION_ERROR = "INGEST_017_DATABASE_TRANSACTION_ERROR"


class RejectionDiagnostic(BaseModel):
    """Sanitized diagnostic detail describing why an event was rejected.
    
    INVARIANT: Never contains passwords, raw payload dumps, or connection strings.
    """
    
    error_code: IngestionErrorCode
    rejection_category: str = Field(..., description="High-level category: schema, privacy, identity, storage")
    explanation: str = Field(..., max_length=512, description="Safe operational explanation")
    field_reference: Optional[str] = Field(None, max_length=128, description="Key or field triggering rejection")

