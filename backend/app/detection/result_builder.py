"""Factory for constructing structured, explainable DetectionResult objects."""

from typing import Any, Dict, List, Optional
from uuid import uuid4
from datetime import datetime, timezone
from app.detection.rule_schema import DetectionRuleDefinition
from app.schemas.detection import DetectionResult, EvaluationStatus


class ResultBuilder:
    """Constructs explainable, tamper-evident DetectionResult records."""

    ENGINE_VERSION = "1.0"

    @classmethod
    def build_result(
        cls,
        rule: DetectionRuleDefinition,
        event: Dict[str, Any],
        status: EvaluationStatus,
        explanation: str,
        matched_conditions: Optional[List[Dict[str, Any]]] = None,
        related_event_ids: Optional[List[str]] = None,
    ) -> DetectionResult:
        """Assembles a DetectionResult preserving evidence references and provenance."""
        event_id = str(event.get("event_id", ""))
        raw_event_id = str(event.get("raw_event_id", ""))
        session_id = str(event.get("session_id", "unknown_session"))
        decoy_id = str(event.get("decoy_id", "unknown_decoy"))
        provenance = event.get("provenance") or {}

        # Construct lightweight evidence link (zero raw secrets or passwords)
        evidence_refs: List[Dict[str, Any]] = [
            {
                "event_id": event_id,
                "raw_event_id": raw_event_id,
                "observed_at": event.get("observed_at"),
                "event_type": event.get("event_type"),
                "action": event.get("action"),
                "outcome": event.get("outcome"),
            }
        ]

        if related_event_ids:
            for rel_id in related_event_ids:
                if rel_id != event_id:
                    evidence_refs.append({"event_id": str(rel_id), "relationship": "correlated_evidence"})

        return DetectionResult(
            detection_result_id=str(uuid4()),
            rule_id=rule.rule_id,
            rule_version=rule.rule_version,
            evaluated_event_id=event_id,
            related_event_ids=[str(r) for r in (related_event_ids or [])],
            session_id=session_id,
            decoy_id=decoy_id,
            evaluation_status=status,
            matched_conditions=matched_conditions or [],
            detection_explanation=explanation,
            evidence_references=evidence_refs,
            evaluated_at=datetime.now(timezone.utc).isoformat(),
            engine_version=cls.ENGINE_VERSION,
            provenance=dict(provenance),
        )

