"""Execution tracking and evaluation idempotency management for SnareSight.

Maintains an audit log of detection executions and enforces idempotent processing
to avoid duplicate detection results on reprocessed events.
"""

import time
from typing import Dict, List, Optional
from uuid import uuid4
from datetime import datetime, timezone
from app.schemas.detection import DetectionExecutionRecord, DetectionResult, EvaluationStatus


class ExecutionTracker:
    """Records detection execution history and prevents duplicate evaluations."""

    def __init__(self, max_history_size: int = 10000):
        self.max_history_size = max_history_size
        # Execution history audit records: [DetectionExecutionRecord, ...]
        self._history: List[DetectionExecutionRecord] = []
        # Idempotency cache: {f"{event_id}:{rule_id}:{rule_version}": DetectionResult}
        self._evaluated_cache: Dict[str, DetectionResult] = {}

    def get_idempotency_key(self, event_id: str, rule_id: str, rule_version: str) -> str:
        """Constructs deterministic idempotency key for single event evaluations."""
        return f"{event_id}:{rule_id}:{rule_version}"

    def has_been_evaluated(self, event_id: str, rule_id: str, rule_version: str) -> bool:
        """Checks if the event was already evaluated against this specific rule version."""
        key = self.get_idempotency_key(event_id, rule_id, rule_version)
        return key in self._evaluated_cache

    def get_cached_result(self, event_id: str, rule_id: str, rule_version: str) -> Optional[DetectionResult]:
        """Returns existing detection result if previously evaluated."""
        key = self.get_idempotency_key(event_id, rule_id, rule_version)
        return self._evaluated_cache.get(key)

    def record_result(self, result: DetectionResult) -> None:
        """Saves a detection result into the idempotency cache."""
        key = self.get_idempotency_key(
            result.evaluated_event_id,
            result.rule_id,
            result.rule_version,
        )
        self._evaluated_cache[key] = result

    def record_execution(
        self,
        rule_id: str,
        rule_version: str,
        event_id: str,
        status: EvaluationStatus,
        duration_ms: float,
        result_id: Optional[str] = None,
        error_category: Optional[str] = None,
    ) -> DetectionExecutionRecord:
        """Records an execution audit entry in memory."""
        record = DetectionExecutionRecord(
            execution_id=str(uuid4()),
            rule_id=rule_id,
            rule_version=rule_version,
            event_id=event_id,
            execution_time=datetime.now(timezone.utc).isoformat(),
            execution_status=status,
            processing_duration_ms=round(duration_ms, 3),
            result_reference=result_id,
            safe_error_category=error_category,
        )

        if len(self._history) >= self.max_history_size:
            self._history.pop(0)

        self._history.append(record)
        return record

    def get_history(self, limit: int = 100) -> List[DetectionExecutionRecord]:
        """Returns recent execution records."""
        return self._history[-limit:]

    def clear(self) -> None:
        """Clears memory stores (used for test isolation)."""
        self._history.clear()
        self._evaluated_cache.clear()


# Default module-level singleton tracker
execution_tracker = ExecutionTracker()

