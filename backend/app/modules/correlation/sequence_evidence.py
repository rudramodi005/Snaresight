"""Evidence Extraction, Validation, and Relationship Construction for Sequences (Task P22)."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.db.models.alert import AlertModel
from app.db.models.correlation import ActivitySessionModel
from app.db.models.intelligence import AttackDetectionMappingModel
from app.modules.correlation.sequence_models import (
    BehavioralSequenceMemberModel,
    BehavioralSequenceRelationshipModel,
    SequenceEvidenceModel,
)
from app.modules.correlation.sequence_schemas import (
    SequenceMemberType,
    SequenceRelationshipType,
)


class SequenceEvidenceBuilder:
    """Constructs auditable evidence records and directed relationship edges between sequence members."""

    @classmethod
    def create_session_member(
        cls,
        sequence_id: str,
        session: ActivitySessionModel,
        position: int,
        reason: str,
        correlation_method: str = "CONTEXTUAL",
    ) -> BehavioralSequenceMemberModel:
        """Instantiates a sequence member record referencing an ActivitySession."""
        now_utc = datetime.now(timezone.utc)
        return BehavioralSequenceMemberModel(
            sequence_id=sequence_id,
            member_type=SequenceMemberType.SESSION.value,
            member_record_id=session.session_id,
            sequence_position=position,
            observed_at=session.first_observed_at,
            relationship_reason=reason,
            correlation_method=correlation_method,
            created_at=now_utc,
        )

    @classmethod
    def create_detection_member(
        cls,
        sequence_id: str,
        alert: AlertModel,
        position: int,
        reason: str,
    ) -> BehavioralSequenceMemberModel:
        """Instantiates a sequence member record referencing a detection Alert."""
        now_utc = datetime.now(timezone.utc)
        return BehavioralSequenceMemberModel(
            sequence_id=sequence_id,
            member_type=SequenceMemberType.DETECTION.value,
            member_record_id=str(alert.alert_id),
            sequence_position=position,
            observed_at=alert.first_observed_at,
            relationship_reason=reason,
            correlation_method="DETECTION_RULE",
            created_at=now_utc,
        )

    @classmethod
    def create_mapping_member(
        cls,
        sequence_id: str,
        mapping: AttackDetectionMappingModel,
        position: int,
        reason: str,
    ) -> BehavioralSequenceMemberModel:
        """Instantiates a sequence member record referencing an ATT&CK mapping."""
        now_utc = datetime.now(timezone.utc)
        return BehavioralSequenceMemberModel(
            sequence_id=sequence_id,
            member_type=SequenceMemberType.ATTACK_MAPPING.value,
            member_record_id=str(mapping.mapping_id),
            sequence_position=position,
            observed_at=mapping.assessed_at,
            relationship_reason=reason,
            correlation_method="MITRE_MAPPING",
            created_at=now_utc,
        )

    @classmethod
    def create_relationship(
        cls,
        sequence_id: str,
        source_member_id: uuid.UUID,
        target_member_id: uuid.UUID,
        rel_type: SequenceRelationshipType,
        explanation: str,
        confidence: int = 70,
        evidence_payload: Optional[Dict[str, Any]] = None,
    ) -> BehavioralSequenceRelationshipModel:
        """Instantiates a directed relationship edge between two sequence members."""
        now_utc = datetime.now(timezone.utc)
        return BehavioralSequenceRelationshipModel(
            sequence_id=sequence_id,
            source_member_id=source_member_id,
            target_member_id=target_member_id,
            relationship_type=rel_type.value,
            explanation=explanation,
            confidence_score=confidence,
            evidence_payload=evidence_payload or {},
            created_at=now_utc,
        )

    @classmethod
    def create_field_evidence(
        cls,
        sequence_id: str,
        record_type: str,
        record_id: str,
        field_name: str,
        field_value: str,
        observed_at: datetime,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> SequenceEvidenceModel:
        """Instantiates an auditable field-level evidence trace."""
        now_utc = datetime.now(timezone.utc)
        return SequenceEvidenceModel(
            sequence_id=sequence_id,
            evidence_record_type=record_type,
            evidence_record_id=record_id,
            field_name=field_name,
            field_value=str(field_value),
            evidence_provenance=provenance or {},
            observed_at=observed_at,
            created_at=now_utc,
        )

