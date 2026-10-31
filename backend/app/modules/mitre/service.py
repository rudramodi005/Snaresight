"""Application service facade for SnareSight MITRE ATT&CK operations."""

import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session
from app.modules.mitre.exceptions import MitreNotFoundError
from app.modules.mitre.importer import MitreImporter
from app.modules.mitre.repository import MitreRepository
from app.modules.mitre.schemas import (
    CatalogueStatusResponse,
    DatasetVersionResponse,
    DryRunPreviewResponse,
    ImportExecutionResponse,
    PaginatedTechniquesResponse,
    RollbackResponse,
    SubtechniqueSchema,
    TacticSchema,
    TechniqueSchema,
)
from app.modules.mitre.versioning import MitreVersioningEngine


class MitreService:
    """Service orchestrator exposing high-level catalogue queries and controlled import operations."""

    @classmethod
    def get_status(cls, db: Session) -> CatalogueStatusResponse:
        """Retrieves operational status of the active MITRE ATT&CK catalogue."""
        return MitreRepository.get_catalogue_status(db)

    @classmethod
    def list_versions(cls, db: Session) -> List[DatasetVersionResponse]:
        """Returns all imported ATT&CK dataset versions."""
        versions = MitreVersioningEngine.list_dataset_versions(db)
        return [
            DatasetVersionResponse(
                domain=v.domain,
                version=v.version,
                stix_version=v.stix_version,
                source_repo=v.source_repo,
                source_filename=v.source_filename,
                retrieval_date=v.retrieval_date.isoformat(),
                release_date=v.release_date.isoformat() if v.release_date else None,
                sha256_checksum=v.sha256_checksum,
                is_active=v.is_active,
                status=v.status,
                object_count=v.object_count,
                created_at=v.created_at.isoformat(),
            )
            for v in versions
        ]

    @classmethod
    def list_tactics(
        cls,
        db: Session,
        version: Optional[str] = None,
        include_deprecated: bool = False,
    ) -> List[TacticSchema]:
        """Returns tactics for the specified (or active) dataset release."""
        active_ver = version or (MitreVersioningEngine.get_active_version(db).version if MitreVersioningEngine.get_active_version(db) else None)
        return MitreRepository.list_tactics(db, version=active_ver, include_deprecated=include_deprecated)

    @classmethod
    def get_tactic(
        cls,
        db: Session,
        tactic_id: str,
        version: Optional[str] = None,
    ) -> TacticSchema:
        """Retrieves single tactic by ID or raises MitreNotFoundError."""
        active_ver = version or (MitreVersioningEngine.get_active_version(db).version if MitreVersioningEngine.get_active_version(db) else None)
        tactic = MitreRepository.get_tactic(db, tactic_id, version=active_ver)
        if not tactic:
            raise MitreNotFoundError(f"Tactic '{tactic_id}' not found in active catalogue")
        return tactic

    @classmethod
    def list_techniques(
        cls,
        db: Session,
        page: int = 1,
        page_size: int = 20,
        search: Optional[str] = None,
        tactic: Optional[str] = None,
        platform: Optional[str] = None,
        status_filter: Optional[str] = None,
        version: Optional[str] = None,
    ) -> PaginatedTechniquesResponse:
        """Returns paginated, searchable ATT&CK techniques."""
        active_ver = version or (MitreVersioningEngine.get_active_version(db).version if MitreVersioningEngine.get_active_version(db) else None)
        total, items = MitreRepository.list_techniques(
            db=db,
            page=page,
            page_size=page_size,
            search=search,
            tactic=tactic,
            platform=platform,
            status_filter=status_filter,
            version=active_ver,
        )
        pages = math.ceil(total / max(1, page_size)) if total > 0 else 0
        return PaginatedTechniquesResponse(
            total=total,
            page=page,
            page_size=page_size,
            pages=pages,
            items=items,
        )

    @classmethod
    def get_technique(
        cls,
        db: Session,
        technique_id: str,
        include_subtechniques: bool = True,
        version: Optional[str] = None,
    ) -> TechniqueSchema:
        """Retrieves single technique and its sub-techniques, or raises MitreNotFoundError."""
        active_ver = version or (MitreVersioningEngine.get_active_version(db).version if MitreVersioningEngine.get_active_version(db) else None)
        technique = MitreRepository.get_technique(
            db=db,
            technique_id=technique_id,
            include_subtechniques=include_subtechniques,
            version=active_ver,
        )
        if not technique:
            raise MitreNotFoundError(f"Technique '{technique_id}' not found in active catalogue")
        return technique

    @classmethod
    def get_subtechnique(
        cls,
        db: Session,
        subtechnique_id: str,
        version: Optional[str] = None,
    ) -> SubtechniqueSchema:
        """Retrieves single sub-technique by external ID (e.g. T1110.001) or raises MitreNotFoundError."""
        active_ver = version or (MitreVersioningEngine.get_active_version(db).version if MitreVersioningEngine.get_active_version(db) else None)
        sub = MitreRepository.get_subtechnique(db, subtechnique_id=subtechnique_id, version=active_ver)
        if not sub:
            raise MitreNotFoundError(f"Sub-technique '{subtechnique_id}' not found in active catalogue")
        return sub

    @classmethod
    def execute_dry_run(
        cls,
        db: Session,
        raw_content: str | bytes | dict,
        filename: str = "enterprise-attack.json",
        version: str = "14.1",
        domain: str = "enterprise-attack",
    ) -> DryRunPreviewResponse:
        """Executes dry-run preview parse."""
        return MitreImporter.execute_dry_run(
            db=db,
            raw_content=raw_content,
            source_filename=filename,
            dataset_version=version,
            dataset_domain=domain,
        )

    @classmethod
    def execute_import(
        cls,
        db: Session,
        raw_content: str | bytes | dict,
        filename: str = "enterprise-attack.json",
        version: str = "14.1",
        domain: str = "enterprise-attack",
        initiated_by: str = "admin",
        activate_immediately: bool = True,
    ) -> ImportExecutionResponse:
        """Executes transactional import."""
        return MitreImporter.execute_import(
            db=db,
            raw_content=raw_content,
            source_filename=filename,
            dataset_version=version,
            dataset_domain=domain,
            initiated_by=initiated_by,
            activate_immediately=activate_immediately,
        )

    @classmethod
    def execute_rollback(
        cls,
        db: Session,
        target_version: Optional[str] = None,
        reason: str = "Manual administrative rollback",
    ) -> RollbackResponse:
        """Rolls back active catalogue version."""
        prev, new_ver = MitreVersioningEngine.rollback_version(
            db=db,
            target_version=target_version,
            reason=reason,
        )
        return RollbackResponse(
            previous_active_version=prev,
            current_active_version=new_ver,
            rollback_status="SUCCESS",
            reason=reason,
            rolled_back_at=datetime.now(timezone.utc).isoformat(),
        )

    @classmethod
    def list_imports(cls, db: Session, limit: int = 20) -> List[Dict[str, Any]]:
        """Returns import history records."""
        runs = MitreRepository.list_import_runs(db, limit=limit)
        return [
            {
                "import_run_id": r.import_run_id,
                "dataset_domain": r.dataset_domain,
                "dataset_version": r.dataset_version,
                "source_filename": r.source_filename,
                "sha256_checksum": r.sha256_checksum,
                "is_dry_run": r.is_dry_run,
                "status": r.status,
                "total_parsed": r.total_parsed,
                "total_accepted": r.total_accepted,
                "execution_duration_ms": r.execution_duration_ms,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            }
            for r in runs
        ]

