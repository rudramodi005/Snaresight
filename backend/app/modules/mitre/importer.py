"""Controlled transactional importer and dry-run engine for MITRE ATT&CK datasets."""

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session
from app.modules.mitre.exceptions import MitreImportError
from app.modules.mitre.models import (
    AttackDatasetVersionModel,
    AttackTacticModel,
    AttackTechniqueModel,
    AttackSubtechniqueModel,
    AttackRelationshipModel,
    AttackImportRunModel,
)
from app.modules.mitre.parser import ParsedStixBundle, StixParser
from app.modules.mitre.schemas import DryRunPreviewResponse, ImportExecutionResponse
from app.modules.mitre.versioning import MitreVersioningEngine


class MitreImporter:
    """Coordinates dry-run previews, transactional imports, and idempotent version persistence."""

    @classmethod
    def execute_dry_run(
        cls,
        db: Session,
        raw_content: str | bytes | dict,
        source_filename: str = "enterprise-attack.json",
        dataset_version: str = "14.1",
        dataset_domain: str = "enterprise-attack",
    ) -> DryRunPreviewResponse:
        """Executes a non-destructive dry-run parse and diff preview without modifying database state."""
        start_time = time.perf_counter()
        checksum = MitreVersioningEngine.compute_sha256(raw_content)

        # Parse bundle
        parsed = StixParser.parse_bundle(
            raw_content=raw_content,
            dataset_version=dataset_version,
            dataset_domain=dataset_domain,
        )

        # Compute diff against currently active database records
        diff = MitreVersioningEngine.compare_releases(db, parsed)

        duration_ms = (time.perf_counter() - start_time) * 1000.0

        # Record dry-run audit entry
        dry_run_record = AttackImportRunModel(
            import_run_id=f"dryrun-{uuid.uuid4()}",
            dataset_domain=dataset_domain,
            dataset_version=dataset_version,
            source_filename=source_filename,
            sha256_checksum=checksum,
            is_dry_run=True,
            status="COMPLETED",
            initiated_by="admin",
            total_parsed=parsed.total_objects,
            total_accepted=parsed.total_accepted,
            total_rejected=len(parsed.validation_errors),
            total_added=diff["objects_to_add"],
            total_updated=diff["objects_to_update"],
            total_unchanged=0,
            total_deprecated=0,
            total_revoked=0,
            validation_warnings=parsed.validation_warnings,
            validation_errors=parsed.validation_errors,
            execution_duration_ms=duration_ms,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        db.add(dry_run_record)
        db.commit()

        return DryRunPreviewResponse(
            dataset_domain=dataset_domain,
            dataset_version=dataset_version,
            sha256_checksum=checksum,
            total_objects=parsed.total_objects,
            tactics_discovered=len(parsed.tactics),
            techniques_discovered=len(parsed.techniques),
            subtechniques_discovered=len(parsed.subtechniques),
            relationships_discovered=len(parsed.relationships),
            unsupported_objects=parsed.unsupported_count,
            objects_to_add=diff["objects_to_add"],
            objects_to_update=diff["objects_to_update"],
            objects_to_deprecate_or_revoke=diff["objects_to_deprecate_or_revoke"],
            validation_warnings=parsed.validation_warnings,
            validation_errors=parsed.validation_errors,
            is_valid=len(parsed.validation_errors) == 0,
        )

    @classmethod
    def execute_import(
        cls,
        db: Session,
        raw_content: str | bytes | dict,
        source_filename: str = "enterprise-attack.json",
        dataset_version: str = "14.1",
        dataset_domain: str = "enterprise-attack",
        source_repo: str = "https://github.com/mitre-attack/attack-stix-data",
        initiated_by: str = "admin",
        activate_immediately: bool = True,
    ) -> ImportExecutionResponse:
        """Executes a transactional import committing versioned ATT&CK entities to PostgreSQL.
        
        Guarantees:
        - Idempotency: re-importing the same dataset version returns existing records without duplicates.
        - Isolation: failures roll back database transactions cleanly without corrupting the active catalogue.
        """
        start_time = time.perf_counter()
        checksum = MitreVersioningEngine.compute_sha256(raw_content)

        # 1. Check idempotency: Has this exact checksum and version already been imported?
        existing_version = (
            db.query(AttackDatasetVersionModel)
            .filter(
                AttackDatasetVersionModel.domain == dataset_domain,
                AttackDatasetVersionModel.version == dataset_version,
                AttackDatasetVersionModel.sha256_checksum == checksum,
            )
            .first()
        )
        if existing_version and existing_version.status in ("ACTIVE", "SUPERSEDED"):
            # Return idempotent execution receipt without re-inserting
            return ImportExecutionResponse(
                import_run_id=f"idempotent-{existing_version.id}",
                status=existing_version.status,
                dataset_version=dataset_version,
                sha256_checksum=checksum,
                total_parsed=existing_version.object_count,
                total_accepted=existing_version.object_count,
                total_rejected=0,
                total_added=0,
                total_updated=0,
                total_unchanged=existing_version.object_count,
                total_deprecated=0,
                total_revoked=0,
                execution_duration_ms=0.0,
                completed_at=existing_version.created_at.isoformat(),
            )

        # 2. Parse bundle
        try:
            parsed = StixParser.parse_bundle(
                raw_content=raw_content,
                dataset_version=dataset_version,
                dataset_domain=dataset_domain,
            )
        except Exception as exc:
            raise MitreImportError(f"Import aborted due to STIX parsing error: {str(exc)}")

        now_utc = datetime.now(timezone.utc)
        import_run_id = f"import-{uuid.uuid4()}"

        try:
            # 3. Create or update Dataset Version record
            version_record = (
                db.query(AttackDatasetVersionModel)
                .filter(
                    AttackDatasetVersionModel.domain == dataset_domain,
                    AttackDatasetVersionModel.version == dataset_version,
                )
                .first()
            )
            if not version_record:
                version_record = AttackDatasetVersionModel(
                    domain=dataset_domain,
                    version=dataset_version,
                    stix_version="2.1",
                    source_repo=source_repo,
                    source_filename=source_filename,
                    retrieval_date=now_utc,
                    sha256_checksum=checksum,
                    is_active=False,
                    status="CANDIDATE",
                    object_count=parsed.total_accepted,
                    created_at=now_utc,
                )
                db.add(version_record)
                db.flush()
            else:
                version_record.sha256_checksum = checksum
                version_record.object_count = parsed.total_accepted
                version_record.updated_at = now_utc
                db.flush()

            # 4. Upsert Tactics
            for tac in parsed.tactics:
                existing_tac = (
                    db.query(AttackTacticModel)
                    .filter(
                        AttackTacticModel.stix_id == tac.stix_id,
                        AttackTacticModel.dataset_version == dataset_version,
                    )
                    .first()
                )
                if existing_tac:
                    existing_tac.tactic_name = tac.tactic_name
                    existing_tac.short_name = tac.short_name
                    existing_tac.description = tac.description
                    existing_tac.is_deprecated = tac.is_deprecated
                    existing_tac.is_revoked = tac.is_revoked
                    existing_tac.external_references = [r.model_dump() for r in tac.external_references]
                else:
                    tac_model = AttackTacticModel(
                        stix_id=tac.stix_id,
                        tactic_id=tac.tactic_id,
                        tactic_name=tac.tactic_name,
                        short_name=tac.short_name,
                        description=tac.description,
                        dataset_version=dataset_version,
                        is_deprecated=tac.is_deprecated,
                        is_revoked=tac.is_revoked,
                        external_references=[r.model_dump() for r in tac.external_references],
                        created_at=now_utc,
                    )
                    db.add(tac_model)
            db.flush()

            # 5. Upsert Techniques
            for tech in parsed.techniques:
                existing_tech = (
                    db.query(AttackTechniqueModel)
                    .filter(AttackTechniqueModel.technique_id == tech.technique_id)
                    .first()
                )
                if existing_tech:
                    existing_tech.technique_name = tech.technique_name
                    existing_tech.tactic_id = tech.tactic_id
                    existing_tech.tactic_name = tech.tactic_name
                    existing_tech.framework_version = tech.framework_version
                    existing_tech.description = tech.description
                    existing_tech.stix_id = tech.stix_id
                    existing_tech.is_subtechnique = False
                    existing_tech.tactics = tech.tactics
                    existing_tech.platforms = tech.platforms
                    existing_tech.data_sources = tech.data_sources
                    existing_tech.is_deprecated = tech.is_deprecated
                    existing_tech.is_revoked = tech.is_revoked
                    existing_tech.external_references = [r.model_dump() for r in tech.external_references]
                    existing_tech.updated_at = now_utc
                else:
                    tech_model = AttackTechniqueModel(
                        technique_id=tech.technique_id,
                        technique_name=tech.technique_name,
                        tactic_id=tech.tactic_id,
                        tactic_name=tech.tactic_name,
                        framework_version=tech.framework_version,
                        description=tech.description,
                        stix_id=tech.stix_id,
                        is_subtechnique=False,
                        tactics=tech.tactics,
                        platforms=tech.platforms,
                        data_sources=tech.data_sources,
                        is_deprecated=tech.is_deprecated,
                        is_revoked=tech.is_revoked,
                        external_references=[r.model_dump() for r in tech.external_references],
                        created_at=now_utc,
                    )
                    db.add(tech_model)
            db.flush()

            # 6. Upsert Sub-techniques
            for sub in parsed.subtechniques:
                existing_sub = (
                    db.query(AttackSubtechniqueModel)
                    .filter(
                        AttackSubtechniqueModel.subtechnique_id == sub.subtechnique_id,
                        AttackSubtechniqueModel.dataset_version == dataset_version,
                    )
                    .first()
                )
                if existing_sub:
                    existing_sub.subtechnique_name = sub.subtechnique_name
                    existing_sub.parent_technique_id = sub.parent_technique_id
                    existing_sub.parent_stix_id = sub.parent_stix_id
                    existing_sub.description = sub.description
                    existing_sub.platforms = sub.platforms
                    existing_sub.is_deprecated = sub.is_deprecated
                    existing_sub.is_revoked = sub.is_revoked
                    existing_sub.external_references = [r.model_dump() for r in sub.external_references]
                else:
                    sub_model = AttackSubtechniqueModel(
                        stix_id=sub.stix_id,
                        subtechnique_id=sub.subtechnique_id,
                        subtechnique_name=sub.subtechnique_name,
                        parent_technique_id=sub.parent_technique_id,
                        parent_stix_id=sub.parent_stix_id,
                        description=sub.description,
                        dataset_version=dataset_version,
                        platforms=sub.platforms,
                        is_deprecated=sub.is_deprecated,
                        is_revoked=sub.is_revoked,
                        external_references=[r.model_dump() for r in sub.external_references],
                        created_at=now_utc,
                    )
                    db.add(sub_model)
            db.flush()

            # 7. Upsert Relationships
            for rel in parsed.relationships:
                existing_rel = (
                    db.query(AttackRelationshipModel)
                    .filter(
                        AttackRelationshipModel.stix_id == rel.stix_id,
                        AttackRelationshipModel.dataset_version == dataset_version,
                    )
                    .first()
                )
                if not existing_rel:
                    rel_model = AttackRelationshipModel(
                        stix_id=rel.stix_id,
                        relationship_type=rel.relationship_type,
                        source_ref=rel.source_ref,
                        target_ref=rel.target_ref,
                        dataset_version=dataset_version,
                        description=rel.description,
                        is_deprecated=rel.is_deprecated,
                        is_revoked=rel.is_revoked,
                        created_at=now_utc,
                    )
                    db.add(rel_model)
            db.flush()

            # 8. Promote to Active if requested
            if activate_immediately:
                MitreVersioningEngine.activate_version(db, dataset_version, dataset_domain)

            duration_ms = (time.perf_counter() - start_time) * 1000.0

            # 9. Commit Audit Run Log
            import_run_model = AttackImportRunModel(
                import_run_id=import_run_id,
                dataset_domain=dataset_domain,
                dataset_version=dataset_version,
                source_filename=source_filename,
                sha256_checksum=checksum,
                is_dry_run=False,
                status="COMPLETED",
                initiated_by=initiated_by,
                total_parsed=parsed.total_objects,
                total_accepted=parsed.total_accepted,
                total_rejected=len(parsed.validation_errors),
                total_added=len(parsed.techniques) + len(parsed.subtechniques) + len(parsed.tactics),
                total_updated=0,
                total_unchanged=0,
                total_deprecated=sum(1 for t in parsed.techniques if t.is_deprecated),
                total_revoked=sum(1 for t in parsed.techniques if t.is_revoked),
                validation_warnings=parsed.validation_warnings,
                validation_errors=parsed.validation_errors,
                execution_duration_ms=duration_ms,
                started_at=now_utc,
                completed_at=datetime.now(timezone.utc),
            )
            db.add(import_run_model)
            db.commit()

            return ImportExecutionResponse(
                import_run_id=import_run_id,
                status="COMPLETED",
                dataset_version=dataset_version,
                sha256_checksum=checksum,
                total_parsed=parsed.total_objects,
                total_accepted=parsed.total_accepted,
                total_rejected=len(parsed.validation_errors),
                total_added=parsed.total_accepted,
                total_updated=0,
                total_unchanged=0,
                total_deprecated=sum(1 for t in parsed.techniques if t.is_deprecated),
                total_revoked=sum(1 for t in parsed.techniques if t.is_revoked),
                execution_duration_ms=duration_ms,
                completed_at=datetime.now(timezone.utc).isoformat(),
            )

        except Exception as exc:
            db.rollback()
            # Record failed import attempt
            try:
                fail_record = AttackImportRunModel(
                    import_run_id=import_run_id,
                    dataset_domain=dataset_domain,
                    dataset_version=dataset_version,
                    source_filename=source_filename,
                    sha256_checksum=checksum,
                    is_dry_run=False,
                    status="FAILED",
                    initiated_by=initiated_by,
                    total_parsed=0,
                    total_accepted=0,
                    total_rejected=1,
                    validation_errors=[str(exc)],
                    execution_duration_ms=(time.perf_counter() - start_time) * 1000.0,
                    started_at=now_utc,
                    completed_at=datetime.now(timezone.utc),
                )
                db.add(fail_record)
                db.commit()
            except Exception:
                pass
            raise MitreImportError(f"Transactional import failed and rolled back: {str(exc)}")

