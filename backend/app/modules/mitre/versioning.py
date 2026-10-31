"""Dataset versioning, release diffing, and cryptographic provenance for MITRE ATT&CK."""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from sqlalchemy.orm import Session
from app.modules.mitre.exceptions import MitreVersionError
from app.modules.mitre.models import AttackDatasetVersionModel, AttackTechniqueModel
from app.modules.mitre.parser import ParsedStixBundle


class MitreVersioningEngine:
    """Manages ATT&CK dataset release lifecycle, provenance checksums, and version transitions."""

    @classmethod
    def compute_sha256(cls, content: bytes | str | dict) -> str:
        """Calculates a deterministic SHA-256 hex digest of raw bundle bytes, string, or dict."""
        if isinstance(content, dict):
            raw_bytes = json.dumps(content, sort_keys=True).encode("utf-8")
        elif isinstance(content, str):
            raw_bytes = content.encode("utf-8")
        elif isinstance(content, (bytes, bytearray)):
            raw_bytes = bytes(content)
        else:
            raw_bytes = str(content).encode("utf-8")
        return hashlib.sha256(raw_bytes).hexdigest()

    @classmethod
    def verify_checksum(cls, content: bytes | str, expected_checksum: str) -> bool:
        """Verifies content matches expected SHA-256 checksum."""
        actual = cls.compute_sha256(content)
        return actual.lower() == expected_checksum.strip().lower()

    @classmethod
    def get_active_version(cls, db: Session, domain: str = "enterprise-attack") -> Optional[AttackDatasetVersionModel]:
        """Retrieves the currently active ATT&CK dataset version for the domain."""
        return (
            db.query(AttackDatasetVersionModel)
            .filter(
                AttackDatasetVersionModel.domain == domain,
                AttackDatasetVersionModel.is_active.is_(True),
            )
            .first()
        )

    @classmethod
    def list_dataset_versions(cls, db: Session, domain: str = "enterprise-attack") -> List[AttackDatasetVersionModel]:
        """Returns all imported or candidate dataset versions ordered by creation time DESC."""
        return (
            db.query(AttackDatasetVersionModel)
            .filter(AttackDatasetVersionModel.domain == domain)
            .order_by(AttackDatasetVersionModel.created_at.desc())
            .all()
        )

    @classmethod
    def activate_version(
        cls,
        db: Session,
        version: str,
        domain: str = "enterprise-attack",
    ) -> AttackDatasetVersionModel:
        """Promotes a candidate dataset version to active, superseding any currently active version."""
        target = (
            db.query(AttackDatasetVersionModel)
            .filter(
                AttackDatasetVersionModel.domain == domain,
                AttackDatasetVersionModel.version == version,
            )
            .first()
        )
        if not target:
            raise MitreVersionError(f"Dataset version '{version}' does not exist in domain '{domain}'")

        # Supersede any currently active version
        active_ver = cls.get_active_version(db, domain)
        if active_ver and active_ver.version != version:
            active_ver.is_active = False
            active_ver.status = "SUPERSEDED"
            active_ver.updated_at = datetime.now(timezone.utc)

        target.is_active = True
        target.status = "ACTIVE"
        target.updated_at = datetime.now(timezone.utc)
        db.flush()
        return target

    @classmethod
    def rollback_version(
        cls,
        db: Session,
        target_version: Optional[str] = None,
        domain: str = "enterprise-attack",
        reason: str = "Manual administrative rollback",
    ) -> Tuple[str, str]:
        """Rolls back the active dataset version to a previous release without deleting historical records.
        
        Returns:
            (previous_version, new_active_version)
        """
        current_active = cls.get_active_version(db, domain)
        if not current_active:
            raise MitreVersionError("No currently active dataset version to rollback from")

        if target_version:
            candidate = (
                db.query(AttackDatasetVersionModel)
                .filter(
                    AttackDatasetVersionModel.domain == domain,
                    AttackDatasetVersionModel.version == target_version,
                )
                .first()
            )
            if not candidate:
                raise MitreVersionError(f"Specified rollback target version '{target_version}' not found")
            next_active = candidate
        else:
            # Find the most recent superseded version
            next_active = (
                db.query(AttackDatasetVersionModel)
                .filter(
                    AttackDatasetVersionModel.domain == domain,
                    AttackDatasetVersionModel.version != current_active.version,
                    AttackDatasetVersionModel.status.in_(["SUPERSEDED", "ACTIVE"]),
                )
                .order_by(AttackDatasetVersionModel.created_at.desc())
                .first()
            )
            if not next_active:
                raise MitreVersionError("No previous active dataset version found for rollback")

        prev_ver_str = current_active.version
        new_ver_str = next_active.version

        current_active.is_active = False
        current_active.status = "ROLLED_BACK"
        current_active.updated_at = datetime.now(timezone.utc)

        next_active.is_active = True
        next_active.status = "ACTIVE"
        next_active.updated_at = datetime.now(timezone.utc)

        db.commit()
        return prev_ver_str, new_ver_str

    @classmethod
    def compare_releases(
        cls,
        db: Session,
        parsed_bundle: ParsedStixBundle,
    ) -> Dict[str, Any]:
        """Computes a structural diff preview comparing incoming bundle with the currently active version."""
        active_ver = cls.get_active_version(db, parsed_bundle.dataset_domain)
        existing_tech_ids: Set[str] = set()

        if active_ver:
            records = (
                db.query(AttackTechniqueModel.technique_id)
                .all()
            )
            existing_tech_ids = {r[0] for r in records}

        incoming_tech_ids = {t.technique_id for t in parsed_bundle.techniques}
        incoming_sub_ids = {s.subtechnique_id for s in parsed_bundle.subtechniques}
        all_incoming_ids = incoming_tech_ids | incoming_sub_ids

        added = len(all_incoming_ids - existing_tech_ids)
        updated = len(all_incoming_ids & existing_tech_ids)
        deprecated_or_revoked = sum(
            1 for t in parsed_bundle.techniques if t.is_deprecated or t.is_revoked
        ) + sum(
            1 for s in parsed_bundle.subtechniques if s.is_deprecated or s.is_revoked
        )

        return {
            "objects_to_add": added,
            "objects_to_update": updated,
            "objects_to_deprecate_or_revoke": deprecated_or_revoked,
        }
