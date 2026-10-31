"""Retention eligibility calculation engine for SnareSight.

Evaluates whether security entities have exceeded their retention window
using trusted server-side timestamps.
"""

from datetime import datetime, timezone, timedelta
from typing import Any
from app.retention.config import RetentionPolicyConfig, retention_config


class RetentionCalculator:
    """Calculates record retention eligibility using trusted server timestamps."""

    @classmethod
    def is_expired(
        cls,
        entity_category: str,
        trusted_timestamp: datetime,
        as_of_time: datetime | None = None,
        policy_config: RetentionPolicyConfig | None = None
    ) -> bool:
        """Determines if a record has exceeded its category-specific retention window.
        
        Args:
            entity_category: e.g. "RAW_EVENTS", "NORMALIZED_EVENTS", "ALERTS", "SIMULATION_EVENTS"
            trusted_timestamp: Server-side timestamp (received_at, created_at, or generated_at).
            as_of_time: Evaluation time (defaults to current UTC time).
            policy_config: Retention configuration to evaluate against.
        """
        cfg = policy_config or retention_config
        retention_days = cfg.get_retention_days(entity_category)
        now_utc = as_of_time or datetime.now(timezone.utc)

        # Ensure trusted timestamp is timezone-aware UTC
        if trusted_timestamp.tzinfo is None:
            ts_utc = trusted_timestamp.replace(tzinfo=timezone.utc)
        else:
            ts_utc = trusted_timestamp.astimezone(timezone.utc)

        cutoff = now_utc - timedelta(days=retention_days)
        return ts_utc < cutoff

    @classmethod
    def get_trusted_timestamp(cls, record: Any, entity_category: str) -> datetime:
        """Extracts the appropriate trusted server timestamp from an entity.
        
        Uses server-recorded timestamps rather than untrusted client-supplied observed_at.
        """
        if hasattr(record, "received_at") and getattr(record, "received_at") is not None:
            return getattr(record, "received_at")
        if hasattr(record, "generated_at") and getattr(record, "generated_at") is not None:
            return getattr(record, "generated_at")
        if hasattr(record, "created_at") and getattr(record, "created_at") is not None:
            return getattr(record, "created_at")
        if hasattr(record, "started_at") and getattr(record, "started_at") is not None:
            return getattr(record, "started_at")

        # Dictionary access fallback
        if isinstance(record, dict):
            for k in ("received_at", "generated_at", "created_at", "started_at"):
                if k in record and record[k] is not None:
                    return record[k]

        # Fail-safe to current time if no server timestamp found (prevents accidental deletion)
        return datetime.now(timezone.utc)

