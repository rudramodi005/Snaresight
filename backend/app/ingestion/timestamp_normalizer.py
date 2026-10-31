"""Timestamp normalization engine for SnareSight event telemetry.

Handles ISO-8601 parsing, UTC conversion, future clock skew detection,
and late-arriving event identification.
"""

from datetime import datetime, timezone, timedelta
from typing import Tuple, Any
from app.ingestion.errors import IngestionErrorCode, RejectionDiagnostic


class TimestampNormalizer:
    """Standardizes heterogeneous timestamp representations into canonical timezone-aware UTC."""

    DEFAULT_FUTURE_SKEW_TOLERANCE_SECONDS = 300  # 5 minutes
    UNUSUAL_DELAY_THRESHOLD_DAYS = 30  # 30 days

    @classmethod
    def parse_to_utc(
        cls,
        raw_ts: Any,
        future_skew_tolerance_seconds: int = DEFAULT_FUTURE_SKEW_TOLERANCE_SECONDS,
        field_name: str = "observed_at"
    ) -> Tuple[datetime | None, bool, RejectionDiagnostic | None]:
        """Parses an ISO-8601 timestamp string or datetime, converts to UTC, and checks tolerances.

        Returns:
            (utc_datetime, is_late_arriving, error_diagnostic)
        """
        if raw_ts is None:
            return None, False, RejectionDiagnostic(
                error_code=IngestionErrorCode.SCHEMA_VALIDATION_FAILED,
                rejection_category="timestamp",
                explanation=f"Required timestamp field '{field_name}' is missing",
                field_reference=field_name,
            )

        # 1. Parse string to datetime
        dt: datetime
        if isinstance(raw_ts, datetime):
            dt = raw_ts
        elif isinstance(raw_ts, str):
            clean_ts = raw_ts.strip()
            # Normalize 'Z' to '+00:00' for fromisoformat
            if clean_ts.endswith("Z"):
                clean_ts = clean_ts[:-1] + "+00:00"
            try:
                dt = datetime.fromisoformat(clean_ts)
            except (ValueError, TypeError) as exc:
                return None, False, RejectionDiagnostic(
                    error_code=IngestionErrorCode.INVALID_TIMESTAMP,
                    rejection_category="timestamp",
                    explanation=f"Invalid ISO-8601 timestamp format for '{field_name}': {str(exc)}",
                    field_reference=field_name,
                )
        else:
            return None, False, RejectionDiagnostic(
                error_code=IngestionErrorCode.INVALID_TIMESTAMP,
                rejection_category="timestamp",
                explanation=f"Timestamp '{field_name}' must be an ISO-8601 string or datetime object",
                field_reference=field_name,
            )

        # 2. Ensure timezone-aware and convert to UTC
        if dt.tzinfo is None:
            # Assume UTC if naive, but ensure timezone is explicit
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)

        now_utc = datetime.now(timezone.utc)

        # 3. Future clock skew detection
        future_limit = now_utc + timedelta(seconds=future_skew_tolerance_seconds)
        if dt > future_limit:
            skew_seconds = int((dt - now_utc).total_seconds())
            return None, False, RejectionDiagnostic(
                error_code=IngestionErrorCode.FUTURE_TIMESTAMP_ANOMALY,
                rejection_category="timestamp_anomaly",
                explanation=f"Timestamp '{field_name}' is {skew_seconds}s in the future (max allowed: {future_skew_tolerance_seconds}s)",
                field_reference=field_name,
            )

        # 4. Late-arriving detection (older than UNUSUAL_DELAY_THRESHOLD_DAYS)
        is_late_arriving = False
        delay_threshold = now_utc - timedelta(days=cls.UNUSUAL_DELAY_THRESHOLD_DAYS)
        if dt < delay_threshold:
            is_late_arriving = True

        return dt, is_late_arriving, None

    @classmethod
    def get_processing_timestamps(
        cls, observed_dt: datetime, received_dt: datetime | None = None
    ) -> Tuple[datetime, datetime, datetime]:
        """Returns standard triplet (observed_at, received_at, normalized_at) all in UTC."""
        now_utc = datetime.now(timezone.utc)
        recv = received_dt if received_dt is not None else now_utc
        norm = now_utc
        return observed_dt, recv, norm
