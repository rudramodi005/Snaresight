"""Evidence quality and strength evaluation engine for SnareSight threat assessments.

Analyzes supporting telemetry, enforces deduplication across evidence references,
validates provenance, checks timestamp consistency, and determines evidence strength.
"""

from typing import Any, Dict, List, Optional, Set, Tuple
from datetime import datetime, timezone
from app.detection.scoring_policy import EvidenceStrength, ProvenanceType


class EvidenceAssessor:
    """Evaluates the completeness, corroboration, and reliability of detection evidence."""

    @classmethod
    def assess_evidence(
        cls,
        event: Dict[str, Any],
        related_events: Optional[List[Dict[str, Any]]] = None,
        evidence_references: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[EvidenceStrength, Dict[str, Any]]:
        """Performs rigorous quality assessment on supporting telemetry.
        
        Returns:
            (evidence_strength, evidence_metrics_dictionary)
        """
        related = related_events or []
        refs = evidence_references or []

        # 1. Deduplicate Evidence References
        seen_event_ids: Set[str] = set()
        unique_evidence_count = 0
        primary_id = str(event.get("event_id", ""))
        if primary_id:
            seen_event_ids.add(primary_id)
            unique_evidence_count += 1

        for ref in refs:
            ref_id = str(ref.get("event_id", ""))
            if ref_id and ref_id not in seen_event_ids:
                seen_event_ids.add(ref_id)
                unique_evidence_count += 1

        for rel in related:
            rel_id = str(rel.get("event_id", ""))
            if rel_id and rel_id not in seen_event_ids:
                seen_event_ids.add(rel_id)
                unique_evidence_count += 1

        # 2. Check Event Validity
        is_valid = event.get("validation_status", "VALID") == "VALID" and bool(event.get("event_type"))

        # 3. Check Session Context
        session_id = event.get("session_id")
        has_session = bool(session_id and str(session_id).startswith("decoy_sess_"))

        # 4. Check Timestamp Quality
        ts_valid, ts_diag = cls._verify_timestamp(event.get("observed_at"))

        # 5. Check Source Reliability
        source_id = event.get("observed_source_id") or event.get("event_source_id")
        source_reliable = bool(source_id)

        # 6. Provenance Categorization
        prov_dict = event.get("provenance") or {}
        raw_source_type = str(prov_dict.get("source_type", "")).upper()
        if "CONTROLLED_TEST" in raw_source_type:
            provenance_type = ProvenanceType.CONTROLLED_TEST
        elif "SYNTHETIC" in raw_source_type:
            provenance_type = ProvenanceType.SYNTHETIC_SIMULATION
        elif "IMPORT" in raw_source_type:
            provenance_type = ProvenanceType.IMPORTED_DATA
        elif "HONEYPOT" in raw_source_type or raw_source_type == "DECOY_INTERACTION":
            provenance_type = ProvenanceType.LIVE_HONEYPOT
        else:
            provenance_type = ProvenanceType.CONTROLLED_TEST if "test" in raw_source_type.lower() else ProvenanceType.LIVE_HONEYPOT

        # 7. Contradictory Evidence Detection
        has_contradiction = False
        contradiction_reason = None
        if event.get("outcome") == "BLOCKED" and event.get("action") == "EXECUTE_PAYLOAD":
            # Action blocked by decoy but claimed executed
            has_contradiction = True
            contradiction_reason = "Payload execution claimed on blocked interaction"

        # 8. Determine Categorical Evidence Strength
        if not is_valid or not ts_valid:
            strength = EvidenceStrength.INSUFFICIENT
        elif unique_evidence_count >= 3 and has_session and source_reliable and not has_contradiction:
            strength = EvidenceStrength.STRONG
        elif unique_evidence_count >= 2 or (has_session and source_reliable):
            strength = EvidenceStrength.MODERATE
        else:
            strength = EvidenceStrength.LIMITED

        metrics = {
            "unique_evidence_count": unique_evidence_count,
            "deduplicated_event_ids": sorted(list(seen_event_ids)),
            "event_valid": is_valid,
            "has_session": has_session,
            "timestamp_valid": ts_valid,
            "timestamp_diagnostic": ts_diag,
            "source_reliable": source_reliable,
            "provenance_type": provenance_type.value,
            "has_contradiction": has_contradiction,
            "contradiction_reason": contradiction_reason,
        }
        return strength, metrics

    @classmethod
    def _verify_timestamp(cls, ts_str: Optional[str]) -> Tuple[bool, str]:
        """Validates timestamp format and check for unfeasible clock skew."""
        if not ts_str:
            return False, "Timestamp is missing"
        try:
            dt = datetime.fromisoformat(ts_str)
            if not dt.tzinfo:
                return False, "Timestamp lacks UTC timezone offset"
            now = datetime.now(timezone.utc)
            # Clock skew check: observed time cannot be > 1 hour into the future
            if dt > now + datetime.resolution * 3600:
                return False, "Timestamp is unfeasibly far in the future"
            return True, "Valid ISO-8601 UTC timestamp"
        except Exception as exc:
            return False, f"Invalid timestamp format: {str(exc)}"

