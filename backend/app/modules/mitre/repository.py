"""Database repository for querying and persisting versioned MITRE ATT&CK entities."""

from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func, or_
from app.modules.mitre.models import (
    AttackDatasetVersionModel,
    AttackTacticModel,
    AttackTechniqueModel,
    AttackSubtechniqueModel,
    AttackRelationshipModel,
    AttackImportRunModel,
)
from app.modules.mitre.schemas import (
    CatalogueStatusResponse,
    ExternalReference,
    SubtechniqueSchema,
    TacticSchema,
    TechniqueSchema,
)


class MitreRepository:
    """Encapsulates SQLAlchemy database queries and upserts for the ATT&CK catalogue."""

    @classmethod
    def get_catalogue_status(cls, db: Session, domain: str = "enterprise-attack") -> CatalogueStatusResponse:
        """Retrieves global operational status and object counts for the active catalogue."""
        active_version_row = (
            db.query(AttackDatasetVersionModel)
            .filter(
                AttackDatasetVersionModel.domain == domain,
                AttackDatasetVersionModel.is_active.is_(True),
            )
            .first()
        )

        if not active_version_row:
            return CatalogueStatusResponse(
                catalogue_available=False,
                active_version=None,
                framework_domain=domain,
                last_import_at=None,
                health_status="EMPTY",
                total_tactics=0,
                total_techniques=0,
                total_subtechniques=0,
                total_relationships=0,
            )

        ver = active_version_row.version
        tactics_count = db.query(func.count(AttackTacticModel.id)).filter(AttackTacticModel.dataset_version == ver).scalar() or 0
        techniques_count = db.query(func.count(AttackTechniqueModel.id)).filter(AttackTechniqueModel.is_subtechnique.is_(False)).scalar() or 0
        subtechniques_count = db.query(func.count(AttackSubtechniqueModel.id)).filter(AttackSubtechniqueModel.dataset_version == ver).scalar() or 0
        relationships_count = db.query(func.count(AttackRelationshipModel.id)).filter(AttackRelationshipModel.dataset_version == ver).scalar() or 0

        last_import = (
            db.query(AttackImportRunModel.completed_at)
            .filter(
                AttackImportRunModel.dataset_domain == domain,
                AttackImportRunModel.is_dry_run.is_(False),
                AttackImportRunModel.status == "COMPLETED",
            )
            .order_by(AttackImportRunModel.completed_at.desc())
            .first()
        )

        return CatalogueStatusResponse(
            catalogue_available=True,
            active_version=ver,
            framework_domain=domain,
            last_import_at=last_import[0].isoformat() if last_import and last_import[0] else None,
            health_status="HEALTHY",
            total_tactics=tactics_count,
            total_techniques=techniques_count,
            total_subtechniques=subtechniques_count,
            total_relationships=relationships_count,
        )

    @classmethod
    def list_tactics(
        cls,
        db: Session,
        version: Optional[str] = None,
        include_deprecated: bool = False,
    ) -> List[TacticSchema]:
        """Queries tactics for the specified version (or active version)."""
        query = db.query(AttackTacticModel)
        if version:
            query = query.filter(AttackTacticModel.dataset_version == version)
        if not include_deprecated:
            query = query.filter(
                AttackTacticModel.is_deprecated.is_(False),
                AttackTacticModel.is_revoked.is_(False),
            )

        records = query.order_by(AttackTacticModel.tactic_id.asc()).all()
        return [
            TacticSchema(
                stix_id=r.stix_id,
                tactic_id=r.tactic_id,
                tactic_name=r.tactic_name,
                short_name=r.short_name,
                description=r.description,
                dataset_version=r.dataset_version,
                is_deprecated=r.is_deprecated,
                is_revoked=r.is_revoked,
                external_references=[ExternalReference(**ref) for ref in (r.external_references or []) if isinstance(ref, dict)],
            )
            for r in records
        ]

    @classmethod
    def get_tactic(
        cls,
        db: Session,
        tactic_id: str,
        version: Optional[str] = None,
    ) -> Optional[TacticSchema]:
        """Queries single tactic by external tactic_id (e.g. TA0001) or short_name."""
        query = db.query(AttackTacticModel).filter(
            or_(
                AttackTacticModel.tactic_id == tactic_id.upper(),
                AttackTacticModel.short_name == tactic_id.lower(),
            )
        )
        if version:
            query = query.filter(AttackTacticModel.dataset_version == version)
        r = query.first()
        if not r:
            return None
        return TacticSchema(
            stix_id=r.stix_id,
            tactic_id=r.tactic_id,
            tactic_name=r.tactic_name,
            short_name=r.short_name,
            description=r.description,
            dataset_version=r.dataset_version,
            is_deprecated=r.is_deprecated,
            is_revoked=r.is_revoked,
            external_references=[ExternalReference(**ref) for ref in (r.external_references or []) if isinstance(ref, dict)],
        )

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
    ) -> Tuple[int, List[TechniqueSchema]]:
        """Queries paginated techniques with search and multi-attribute filtering."""
        query = db.query(AttackTechniqueModel).filter(AttackTechniqueModel.is_subtechnique.is_(False))

        if search and search.strip():
            term = f"%{search.strip().lower()}%"
            query = query.filter(
                or_(
                    func.lower(AttackTechniqueModel.technique_id).like(term),
                    func.lower(AttackTechniqueModel.technique_name).like(term),
                    func.lower(AttackTechniqueModel.description).like(term),
                )
            )

        if tactic and tactic.strip():
            t_term = tactic.strip().lower()
            query = query.filter(
                or_(
                    func.lower(AttackTechniqueModel.tactic_id) == t_term.upper(),
                    func.lower(AttackTechniqueModel.tactic_name) == t_term,
                )
            )

        if status_filter == "ACTIVE":
            query = query.filter(
                AttackTechniqueModel.is_deprecated.is_(False),
                AttackTechniqueModel.is_revoked.is_(False),
            )
        elif status_filter == "DEPRECATED":
            query = query.filter(AttackTechniqueModel.is_deprecated.is_(True))
        elif status_filter == "REVOKED":
            query = query.filter(AttackTechniqueModel.is_revoked.is_(True))

        total = query.count()
        offset = max(0, (page - 1) * page_size)
        records = query.order_by(AttackTechniqueModel.technique_id.asc()).offset(offset).limit(page_size).all()

        items = [
            TechniqueSchema(
                stix_id=r.stix_id,
                technique_id=r.technique_id,
                technique_name=r.technique_name,
                tactic_id=r.tactic_id,
                tactic_name=r.tactic_name,
                framework_version=r.framework_version,
                description=r.description,
                is_subtechnique=r.is_subtechnique,
                tactics=r.tactics or [],
                platforms=r.platforms or [],
                data_sources=r.data_sources or [],
                is_deprecated=r.is_deprecated,
                is_revoked=r.is_revoked,
                external_references=[ExternalReference(**ref) for ref in (r.external_references or []) if isinstance(ref, dict)],
                subtechniques=[],
            )
            for r in records
        ]

        return total, items

    @classmethod
    def get_technique(
        cls,
        db: Session,
        technique_id: str,
        include_subtechniques: bool = True,
        version: Optional[str] = None,
    ) -> Optional[TechniqueSchema]:
        """Queries single technique by external ID (e.g. T1110)."""
        r = (
            db.query(AttackTechniqueModel)
            .filter(func.upper(AttackTechniqueModel.technique_id) == technique_id.strip().upper())
            .first()
        )
        if not r:
            return None

        subtechs: List[SubtechniqueSchema] = []
        if include_subtechniques:
            sub_query = db.query(AttackSubtechniqueModel).filter(
                AttackSubtechniqueModel.parent_technique_id == r.technique_id
            )
            if version:
                sub_query = sub_query.filter(AttackSubtechniqueModel.dataset_version == version)
            sub_records = sub_query.order_by(AttackSubtechniqueModel.subtechnique_id.asc()).all()
            subtechs = [
                SubtechniqueSchema(
                    stix_id=s.stix_id,
                    subtechnique_id=s.subtechnique_id,
                    subtechnique_name=s.subtechnique_name,
                    parent_technique_id=s.parent_technique_id,
                    parent_stix_id=s.parent_stix_id,
                    description=s.description,
                    dataset_version=s.dataset_version,
                    platforms=s.platforms or [],
                    is_deprecated=s.is_deprecated,
                    is_revoked=s.is_revoked,
                    external_references=[ExternalReference(**ref) for ref in (s.external_references or []) if isinstance(ref, dict)],
                )
                for s in sub_records
            ]

        return TechniqueSchema(
            stix_id=r.stix_id,
            technique_id=r.technique_id,
            technique_name=r.technique_name,
            tactic_id=r.tactic_id,
            tactic_name=r.tactic_name,
            framework_version=r.framework_version,
            description=r.description,
            is_subtechnique=r.is_subtechnique,
            tactics=r.tactics or [],
            platforms=r.platforms or [],
            data_sources=r.data_sources or [],
            is_deprecated=r.is_deprecated,
            is_revoked=r.is_revoked,
            external_references=[ExternalReference(**ref) for ref in (r.external_references or []) if isinstance(ref, dict)],
            subtechniques=subtechs,
        )

    @classmethod
    def get_subtechnique(
        cls,
        db: Session,
        subtechnique_id: str,
        version: Optional[str] = None,
    ) -> Optional[SubtechniqueSchema]:
        """Queries single sub-technique by external ID (e.g. T1110.001)."""
        query = db.query(AttackSubtechniqueModel).filter(
            func.upper(AttackSubtechniqueModel.subtechnique_id) == subtechnique_id.strip().upper()
        )
        if version:
            query = query.filter(AttackSubtechniqueModel.dataset_version == version)
        s = query.first()
        if not s:
            return None
        return SubtechniqueSchema(
            stix_id=s.stix_id,
            subtechnique_id=s.subtechnique_id,
            subtechnique_name=s.subtechnique_name,
            parent_technique_id=s.parent_technique_id,
            parent_stix_id=s.parent_stix_id,
            description=s.description,
            dataset_version=s.dataset_version,
            platforms=s.platforms or [],
            is_deprecated=s.is_deprecated,
            is_revoked=s.is_revoked,
            external_references=[ExternalReference(**ref) for ref in (s.external_references or []) if isinstance(ref, dict)],
        )

    @classmethod
    def list_import_runs(cls, db: Session, limit: int = 20) -> List[AttackImportRunModel]:
        """Returns historical import operations ordered by start time DESC."""
        return (
            db.query(AttackImportRunModel)
            .order_by(AttackImportRunModel.started_at.desc())
            .limit(min(limit, 100))
            .all()
        )

