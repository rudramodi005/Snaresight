"""Service layer for MITRE ATT&CK Threat Intelligence & Mapping Dashboard (Task P29)."""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc, asc, or_, and_, func

from app.db.models.intelligence import (
    AttackDatasetVersionModel,
    AttackTacticModel,
    AttackTechniqueModel,
    AttackSubtechniqueModel,
    AttackMappingDefinitionModel,
    AttackDetectionMappingModel,
    AttackMappingEvidenceModel,
    AttackMappingReviewModel,
    AttackMappingHistoryModel,
)
from app.db.models.rule import DetectionRuleModel
from app.db.models.alert import AlertModel
from app.db.models.event import SecurityEventModel
from app.db.models.campaign import ClusterMembershipModel, InvestigationClusterModel
from app.modules.mitre.importer import MitreImporter
from app.modules.mitre.mapping.registry import mapping_registry
from app.modules.mitre.dashboard_schemas import (
    AttackCatalogueMetadata,
    AttackDashboardSummary,
    AttackTacticOverviewItem,
    AttackTacticOverviewResponse,
    AttackMatrixCell,
    AttackMatrixColumn,
    AttackMatrixResponse,
    AttackTechniqueExplorerItem,
    AttackTechniqueExplorerResponse,
    AttackTechniqueDetailResponse,
    AttackTechniqueMappingItem,
    AttackTechniqueEvidenceItem,
    AttackCoverageAnalyticsResponse,
    TacticCoverageItem,
    AttackTraceabilityItem,
    AttackTraceabilityResponse,
    MappingReviewActionRequest,
)


class AttackDashboardService:
    """Orchestrates ATT&CK catalogue metrics, interactive matrix generation, explorer, and traceability."""

    # Canonical Enterprise ATT&CK Tactic Order
    CANONICAL_TACTIC_ORDER = [
        "TA0043",  # Reconnaissance
        "TA0042",  # Resource Development
        "TA0001",  # Initial Access
        "TA0002",  # Execution
        "TA0003",  # Persistence
        "TA0004",  # Privilege Escalation
        "TA0005",  # Defense Evasion
        "TA0006",  # Credential Access
        "TA0007",  # Discovery
        "TA0008",  # Lateral Movement
        "TA0009",  # Collection
        "TA0011",  # Command and Control
        "TA0010",  # Exfiltration
        "TA0040",  # Impact
    ]

    @classmethod
    def ensure_catalogue_initialized(cls, db: Session) -> AttackDatasetVersionModel:
        """Verifies an active catalogue release exists; if empty, automatically seeds from local STIX bundle."""
        active = (
            db.query(AttackDatasetVersionModel)
            .filter(
                AttackDatasetVersionModel.domain == "enterprise-attack",
                AttackDatasetVersionModel.is_active.is_(True),
            )
            .first()
        )
        if active:
            return active

        # Auto-seed from bundled STIX release
        data_path = Path(__file__).resolve().parent / "data" / "enterprise-attack-v14.1.json"
        if data_path.exists():
            with open(data_path, "r", encoding="utf-8") as f:
                content = f.read()
            MitreImporter.execute_import(
                db=db,
                raw_content=content,
                source_filename="enterprise-attack-v14.1.json",
                dataset_version="14.1",
                dataset_domain="enterprise-attack",
                activate_immediately=True,
            )
            active = (
                db.query(AttackDatasetVersionModel)
                .filter(
                    AttackDatasetVersionModel.domain == "enterprise-attack",
                    AttackDatasetVersionModel.is_active.is_(True),
                )
                .first()
            )
        return active

    @classmethod
    def get_catalogue_metadata(cls, db: Session) -> AttackCatalogueMetadata:
        """Returns metadata for the active catalogue release."""
        active = cls.ensure_catalogue_initialized(db)
        now_iso = datetime.now(timezone.utc).isoformat()
        if not active:
            return AttackCatalogueMetadata(
                domain="enterprise-attack",
                version="v14.1",
                last_updated_at=now_iso,
            )
        return AttackCatalogueMetadata(
            domain=active.domain,
            version=f"v{active.version}" if not active.version.startswith("v") else active.version,
            stix_version=active.stix_version,
            source_repo=active.source_repo,
            sha256_checksum=active.sha256_checksum,
            retrieval_date=active.retrieval_date.isoformat() if active.retrieval_date else None,
            release_date=active.release_date.isoformat() if active.release_date else None,
            is_active=active.is_active,
            status=active.status,
            total_objects=active.object_count,
            mapping_registry_version="v1.0",
            last_updated_at=active.created_at.isoformat(),
        )

    @classmethod
    def get_summary(cls, db: Session) -> AttackDashboardSummary:
        """Calculates real-time aggregate metrics across catalogue, mappings, and live alerts."""
        cls.ensure_catalogue_initialized(db)
        meta = cls.get_catalogue_metadata(db)

        # 1. Catalogue technique counts
        total_techniques = db.query(AttackTechniqueModel).count()
        total_subtechniques = db.query(AttackSubtechniqueModel).count()
        total_tactics = db.query(AttackTacticModel).count()

        # 2. Registered mapping definitions
        registry_defs = mapping_registry.list_all_definitions(active_only=True)
        mapped_tech_ids = {d.technique_id for d in registry_defs}

        # 3. Live detection mappings in database
        live_mappings = db.query(AttackDetectionMappingModel).all()
        for lm in live_mappings:
            mapped_tech_ids.add(lm.technique_id)

        # 4. Techniques with supporting alert evidence
        alert_backed_tech_ids = set()
        for lm in live_mappings:
            if lm.alert_id:
                alert_backed_tech_ids.add(lm.technique_id)

        # 5. Pending review count
        pending_review_count = (
            db.query(AttackDetectionMappingModel)
            .filter(AttackDetectionMappingModel.review_status == "PENDING")
            .count()
        )

        # 6. Detection rule coverage
        all_rules = db.query(DetectionRuleModel).all()
        all_rule_ids = {r.rule_id for r in all_rules}
        mapped_rule_ids = {d.rule_id for d in registry_defs}
        for lm in live_mappings:
            mapped_rule_ids.add(lm.rule_id)

        rules_mapped_count = len(all_rule_ids.intersection(mapped_rule_ids))
        rules_unmapped_count = len(all_rule_ids - mapped_rule_ids)

        return AttackDashboardSummary(
            total_catalogue_techniques=total_techniques,
            total_catalogue_subtechniques=total_subtechniques,
            total_catalogue_tactics=total_tactics,
            techniques_mapped_to_detections=len(mapped_tech_ids),
            techniques_with_alert_evidence=len(alert_backed_tech_ids),
            techniques_pending_review=pending_review_count,
            detection_rules_mapped=rules_mapped_count,
            detection_rules_unmapped=rules_unmapped_count,
            catalogue_metadata=meta,
            last_refreshed_at=datetime.now(timezone.utc).isoformat(),
        )

    @classmethod
    def get_tactic_overview(cls, db: Session) -> AttackTacticOverviewResponse:
        """Returns Enterprise ATT&CK tactics with counts of mapped techniques, rules, and alerts."""
        cls.ensure_catalogue_initialized(db)

        tactics = db.query(AttackTacticModel).all()
        tactic_map = {t.tactic_id: t for t in tactics}

        # Order tactics canonically
        ordered_tactics: List[AttackTacticModel] = []
        for tid in cls.CANONICAL_TACTIC_ORDER:
            if tid in tactic_map:
                ordered_tactics.append(tactic_map[tid])
        for t in tactics:
            if t not in ordered_tactics:
                ordered_tactics.append(t)

        registry_defs = mapping_registry.list_all_definitions(active_only=True)
        live_mappings = db.query(AttackDetectionMappingModel).all()

        items: List[AttackTacticOverviewItem] = []
        for t in ordered_tactics:
            # Find techniques belonging to this tactic
            techniques_in_tactic = (
                db.query(AttackTechniqueModel)
                .filter(
                    (AttackTechniqueModel.tactic_id == t.tactic_id) |
                    (AttackTechniqueModel.tactic_name == t.tactic_name)
                )
                .all()
            )
            tech_ids = {tech.technique_id for tech in techniques_in_tactic}

            # Mapped techniques & supporting rules
            t_mapped_techs = set()
            t_supporting_rules = set()
            for d in registry_defs:
                if d.technique_id in tech_ids:
                    t_mapped_techs.add(d.technique_id)
                    t_supporting_rules.add(d.rule_id)

            t_alert_count = 0
            for lm in live_mappings:
                if lm.technique_id in tech_ids:
                    t_mapped_techs.add(lm.technique_id)
                    t_supporting_rules.add(lm.rule_id)
                    if lm.alert_id:
                        t_alert_count += 1

            # Count campaign investigations referencing these techniques/rules
            investigations_count = 0
            if t_supporting_rules:
                investigations_count = (
                    db.query(InvestigationClusterModel)
                    .join(ClusterMembershipModel, InvestigationClusterModel.cluster_id == ClusterMembershipModel.cluster_id)
                    .filter(ClusterMembershipModel.member_type.in_(["RULE", "ALERT"]))
                    .distinct()
                    .count()
                )

            items.append(
                AttackTacticOverviewItem(
                    tactic_id=t.tactic_id,
                    tactic_name=t.tactic_name,
                    short_name=t.short_name,
                    description=t.description,
                    mapped_techniques_count=len(t_mapped_techs),
                    supporting_rules_count=len(t_supporting_rules),
                    related_alerts_count=t_alert_count,
                    investigations_referencing_count=investigations_count,
                )
            )

        return AttackTacticOverviewResponse(
            total_tactics=len(items),
            tactics=items,
        )

    @classmethod
    def get_matrix(
        cls,
        db: Session,
        filter_tactic: Optional[str] = None,
        filter_status: Optional[str] = None,
        search: Optional[str] = None,
    ) -> AttackMatrixResponse:
        """Builds the multi-column interactive Enterprise ATT&CK matrix."""
        cls.ensure_catalogue_initialized(db)
        meta = cls.get_catalogue_metadata(db)

        # 1. Load active definitions and live mappings
        registry_defs = mapping_registry.list_all_definitions(active_only=True)
        rule_map_by_tech: Dict[str, List[str]] = {}
        for d in registry_defs:
            rule_map_by_tech.setdefault(d.technique_id, []).append(d.rule_id)

        live_mappings = db.query(AttackDetectionMappingModel).all()
        alert_counts_by_tech: Dict[str, int] = {}
        review_pending_by_tech: Dict[str, bool] = {}

        for lm in live_mappings:
            rule_map_by_tech.setdefault(lm.technique_id, []).append(lm.rule_id)
            if lm.alert_id:
                alert_counts_by_tech[lm.technique_id] = alert_counts_by_tech.get(lm.technique_id, 0) + 1
            if lm.review_status == "PENDING" or lm.mapping_category == "REQUIRES_ANALYST_REVIEW":
                review_pending_by_tech[lm.technique_id] = True

        # 2. Query tactics
        tactics = db.query(AttackTacticModel).all()
        tactic_dict = {t.tactic_id: t for t in tactics}

        ordered_tactics: List[AttackTacticModel] = []
        for tid in cls.CANONICAL_TACTIC_ORDER:
            if tid in tactic_dict:
                ordered_tactics.append(tactic_dict[tid])
        for t in tactics:
            if t not in ordered_tactics:
                ordered_tactics.append(t)

        if filter_tactic:
            ft_upper = filter_tactic.strip().upper()
            ordered_tactics = [
                t for t in ordered_tactics
                if t.tactic_id.upper() == ft_upper or t.short_name.upper() == ft_upper or t.tactic_name.upper() == ft_upper
            ]

        # 3. Build Columns
        columns: List[AttackMatrixColumn] = []
        for t in ordered_tactics:
            tech_query = db.query(AttackTechniqueModel).filter(
                (AttackTechniqueModel.tactic_id == t.tactic_id) |
                (AttackTechniqueModel.tactic_name == t.tactic_name)
            )

            techniques = tech_query.order_by(asc(AttackTechniqueModel.technique_id)).all()
            cells: List[AttackMatrixCell] = []

            for tech in techniques:
                # Text search filter
                if search and search.strip():
                    sterm = search.strip().lower()
                    if sterm not in tech.technique_id.lower() and sterm not in tech.technique_name.lower():
                        continue

                mapped_rules = list(set(rule_map_by_tech.get(tech.technique_id, [])))
                alerts_cnt = alert_counts_by_tech.get(tech.technique_id, 0)
                req_review = review_pending_by_tech.get(tech.technique_id, False)

                # Determine status
                if req_review:
                    status = "REVIEW_REQUIRED"
                elif alerts_cnt > 0:
                    status = "ALERT_EVIDENCE"
                elif len(mapped_rules) > 0:
                    status = "RULE_MAPPED"
                else:
                    status = "UNMAPPED"

                # Filter by status if requested
                if filter_status:
                    fs = filter_status.strip().upper()
                    if fs != status:
                        continue

                sub_cnt = db.query(AttackSubtechniqueModel).filter(
                    AttackSubtechniqueModel.parent_technique_id == tech.technique_id
                ).count()

                cells.append(
                    AttackMatrixCell(
                        technique_id=tech.technique_id,
                        technique_name=tech.technique_name,
                        is_subtechnique=tech.is_subtechnique,
                        parent_technique_id=None,
                        mapping_status=status,
                        mapped_rules=mapped_rules,
                        alert_count=alerts_cnt,
                        requires_review=req_review,
                        confidence=85 if alerts_cnt > 0 else (70 if mapped_rules else None),
                        subtechnique_count=sub_cnt,
                    )
                )

            columns.append(
                AttackMatrixColumn(
                    tactic_id=t.tactic_id,
                    tactic_name=t.tactic_name,
                    short_name=t.short_name,
                    techniques=cells,
                )
            )

        return AttackMatrixResponse(
            domain=meta.domain,
            version=meta.version,
            columns=columns,
        )

    @classmethod
    def list_techniques_explorer(
        cls,
        db: Session,
        page: int = 1,
        page_size: int = 25,
        search: Optional[str] = None,
        tactic: Optional[str] = None,
        status_filter: Optional[str] = None,
        is_subtechnique: Optional[bool] = None,
        sort_by: str = "technique_id",
        sort_order: str = "asc",
    ) -> AttackTechniqueExplorerResponse:
        """Retrieves server-side filtered, searchable, and paginated techniques."""
        cls.ensure_catalogue_initialized(db)

        # Pre-calculate mapping metadata
        registry_defs = mapping_registry.list_all_definitions(active_only=True)
        rule_map_by_tech: Dict[str, List[str]] = {}
        for d in registry_defs:
            rule_map_by_tech.setdefault(d.technique_id, []).append(d.rule_id)

        live_mappings = db.query(AttackDetectionMappingModel).all()
        alert_counts_by_tech: Dict[str, int] = {}
        review_status_by_tech: Dict[str, str] = {}

        for lm in live_mappings:
            rule_map_by_tech.setdefault(lm.technique_id, []).append(lm.rule_id)
            if lm.alert_id:
                alert_counts_by_tech[lm.technique_id] = alert_counts_by_tech.get(lm.technique_id, 0) + 1
            if lm.review_status:
                review_status_by_tech[lm.technique_id] = lm.review_status

        # Query techniques
        query = db.query(AttackTechniqueModel)

        if tactic:
            tupper = tactic.strip().upper()
            query = query.filter(
                or_(
                    AttackTechniqueModel.tactic_id.ilike(f"%{tupper}%"),
                    AttackTechniqueModel.tactic_name.ilike(f"%{tupper}%"),
                )
            )

        if is_subtechnique is not None:
            query = query.filter(AttackTechniqueModel.is_subtechnique == is_subtechnique)

        if search and search.strip():
            term = f"%{search.strip()}%"
            query = query.filter(
                or_(
                    AttackTechniqueModel.technique_id.ilike(term),
                    AttackTechniqueModel.technique_name.ilike(term),
                    AttackTechniqueModel.description.ilike(term),
                    AttackTechniqueModel.tactic_name.ilike(term),
                )
            )

        # Fetch all matching to evaluate dynamic status filters
        all_matches = query.all()

        filtered_items: List[AttackTechniqueModel] = []
        for tech in all_matches:
            mapped_rules = list(set(rule_map_by_tech.get(tech.technique_id, [])))
            alerts_cnt = alert_counts_by_tech.get(tech.technique_id, 0)
            rev_st = review_status_by_tech.get(tech.technique_id, "NONE")

            if rev_st == "PENDING":
                m_status = "REVIEW_REQUIRED"
            elif alerts_cnt > 0:
                m_status = "ALERT_EVIDENCE"
            elif len(mapped_rules) > 0:
                m_status = "RULE_MAPPED"
            else:
                m_status = "UNMAPPED"

            if status_filter:
                sf = status_filter.strip().upper()
                if sf == "MAPPED" and m_status == "UNMAPPED":
                    continue
                elif sf == "UNMAPPED" and m_status != "UNMAPPED":
                    continue
                elif sf in ("RULE_MAPPED", "ALERT_EVIDENCE", "REVIEW_REQUIRED") and m_status != sf:
                    continue

            filtered_items.append(tech)

        total = len(filtered_items)

        # Sorting
        reverse = sort_order.lower() == "desc"
        if sort_by == "technique_name":
            filtered_items.sort(key=lambda x: x.technique_name, reverse=reverse)
        elif sort_by == "tactic_name":
            filtered_items.sort(key=lambda x: x.tactic_name or "", reverse=reverse)
        else:
            filtered_items.sort(key=lambda x: x.technique_id, reverse=reverse)

        # Pagination
        offset = max(0, (page - 1) * page_size)
        paged_items = filtered_items[offset : offset + page_size]
        total_pages = max(1, (total + page_size - 1) // page_size)

        result_items: List[AttackTechniqueExplorerItem] = []
        for tech in paged_items:
            mapped_rules = list(set(rule_map_by_tech.get(tech.technique_id, [])))
            alerts_cnt = alert_counts_by_tech.get(tech.technique_id, 0)
            rev_st = review_status_by_tech.get(tech.technique_id, "ACCEPTED" if mapped_rules else "NONE")

            if rev_st == "PENDING":
                m_status = "REVIEW_REQUIRED"
            elif alerts_cnt > 0:
                m_status = "ALERT_EVIDENCE"
            elif len(mapped_rules) > 0:
                m_status = "RULE_MAPPED"
            else:
                m_status = "UNMAPPED"

            result_items.append(
                AttackTechniqueExplorerItem(
                    technique_id=tech.technique_id,
                    technique_name=tech.technique_name,
                    tactic_id=tech.tactic_id,
                    tactic_name=tech.tactic_name,
                    is_subtechnique=tech.is_subtechnique,
                    parent_technique_id=None,
                    mapping_status=m_status,
                    mapped_rules_count=len(mapped_rules),
                    mapped_rules=mapped_rules,
                    alert_evidence_count=alerts_cnt,
                    review_status=rev_st,
                    confidence=85 if alerts_cnt > 0 else (70 if mapped_rules else None),
                )
            )

        return AttackTechniqueExplorerResponse(
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            items=result_items,
        )

    @classmethod
    def get_technique_detail(cls, db: Session, technique_id: str) -> Optional[AttackTechniqueDetailResponse]:
        """Retrieves comprehensive official ATT&CK context, SnareSight mappings, and alert evidence."""
        cls.ensure_catalogue_initialized(db)

        tid = technique_id.strip().upper()
        tech = (
            db.query(AttackTechniqueModel)
            .filter(AttackTechniqueModel.technique_id == tid)
            .first()
        )
        if not tech:
            return None

        # 1. Sub-techniques
        subtechs = (
            db.query(AttackSubtechniqueModel)
            .filter(AttackSubtechniqueModel.parent_technique_id == tid)
            .all()
        )
        subtech_list = [
            {"subtechnique_id": s.subtechnique_id, "subtechnique_name": s.subtechnique_name}
            for s in subtechs
        ]

        # 2. Configured Mapping Definitions
        registry_defs = [
            d for d in mapping_registry.list_all_definitions(active_only=True)
            if d.technique_id == tid or (d.subtechnique_id and d.subtechnique_id == tid)
        ]

        mapping_items: List[AttackTechniqueMappingItem] = []
        for d in registry_defs:
            rule = db.query(DetectionRuleModel).filter(DetectionRuleModel.rule_id == d.rule_id).first()
            mapping_items.append(
                AttackTechniqueMappingItem(
                    mapping_definition_id=d.mapping_definition_id,
                    rule_id=d.rule_id,
                    rule_name=rule.rule_name if rule else d.rule_id,
                    rule_version=d.rule_version_range,
                    mapping_category=d.mapping_category.value if hasattr(d.mapping_category, "value") else str(d.mapping_category),
                    default_confidence=d.default_confidence,
                    mapping_rationale=d.mapping_rationale,
                    is_active=d.is_active,
                    documentation_reference=d.documentation_reference,
                )
            )

        # 3. Live Supporting Evidence (Alerts & Events)
        evidence_items: List[AttackTechniqueEvidenceItem] = []
        live_mappings = (
            db.query(AttackDetectionMappingModel)
            .filter(AttackDetectionMappingModel.technique_id == tid)
            .all()
        )

        for lm in live_mappings:
            if lm.alert_id:
                alert = db.query(AlertModel).filter(AlertModel.alert_id == lm.alert_id).first()
                if alert:
                    evidence_items.append(
                        AttackTechniqueEvidenceItem(
                            evidence_id=str(lm.mapping_id),
                            evidence_type="SECURITY_ALERT",
                            record_id=str(alert.alert_id),
                            observed_at=alert.generated_at.isoformat() if alert.generated_at else None,
                            supporting_rule_id=lm.rule_id,
                            source_ip=alert.source_address,
                            decoy_id=alert.decoy_id,
                            severity=alert.severity,
                            confidence=alert.confidence,
                            navigation_url=f"/alerts?alert_id={alert.alert_id}",
                        )
                    )

        # 4. Status determination
        has_alerts = len(evidence_items) > 0
        has_mappings = len(mapping_items) > 0
        requires_review = any(lm.review_status == "PENDING" for lm in live_mappings) or any(
            d.mapping_category == "REQUIRES_ANALYST_REVIEW" for d in mapping_items
        )

        if requires_review:
            m_status = "REVIEW_REQUIRED"
        elif has_alerts:
            m_status = "ALERT_EVIDENCE"
        elif has_mappings:
            m_status = "RULE_MAPPED"
        else:
            m_status = "UNMAPPED"

        # 5. Platforms
        plat_list = tech.platforms if isinstance(tech.platforms, list) else ["Linux", "Windows", "Network"]

        return AttackTechniqueDetailResponse(
            technique_id=tech.technique_id,
            technique_name=tech.technique_name,
            description=tech.description or "Official Enterprise ATT&CK technique description.",
            tactic_id=tech.tactic_id,
            tactic_name=tech.tactic_name,
            framework_version=tech.framework_version,
            is_subtechnique=tech.is_subtechnique,
            parent_technique_id=None,
            parent_technique_name=None,
            subtechniques=subtech_list,
            official_reference_url=f"https://attack.mitre.org/techniques/{tech.technique_id}/",
            platforms=plat_list,
            mapping_status=m_status,
            mappings=mapping_items,
            supporting_evidence=evidence_items,
            recent_reviews=[
                {"review_status": lm.review_status, "comment": lm.review_comment, "reviewed_by": lm.reviewed_by}
                for lm in live_mappings if lm.review_status
            ],
        )

    @classmethod
    def get_coverage_analytics(cls, db: Session) -> AttackCoverageAnalyticsResponse:
        """Calculates exact mapping and alert evidence coverage percentages."""
        cls.ensure_catalogue_initialized(db)
        meta = cls.get_catalogue_metadata(db)

        # 1. Total active catalogue techniques
        total_techs = db.query(AttackTechniqueModel).count()

        # 2. Mapped techniques & evidence
        registry_defs = mapping_registry.list_all_definitions(active_only=True)
        tech_to_rules: Dict[str, Set[str]] = {}
        for d in registry_defs:
            tech_to_rules.setdefault(d.technique_id, set()).add(d.rule_id)

        live_mappings = db.query(AttackDetectionMappingModel).all()
        evidence_backed_techs: Set[str] = set()
        pending_review_count = 0

        for lm in live_mappings:
            tech_to_rules.setdefault(lm.technique_id, set()).add(lm.rule_id)
            if lm.alert_id:
                evidence_backed_techs.add(lm.technique_id)
            if lm.review_status == "PENDING":
                pending_review_count += 1

        mapped_techs = set(tech_to_rules.keys())
        total_mapped = len(mapped_techs)
        total_evidence = len(evidence_backed_techs)

        mapping_pct = round((total_mapped / total_techs * 100.0) if total_techs > 0 else 0.0, 2)
        evidence_pct = round((total_evidence / total_techs * 100.0) if total_techs > 0 else 0.0, 2)

        # 3. Detection rule coverage
        all_rules = db.query(DetectionRuleModel).all()
        all_rule_ids = {r.rule_id for r in all_rules}
        all_mapped_rule_ids = {d.rule_id for d in registry_defs}
        for lm in live_mappings:
            all_mapped_rule_ids.add(lm.rule_id)

        rules_mapped = len(all_rule_ids.intersection(all_mapped_rule_ids))
        unmapped_rules = sorted(list(all_rule_ids - all_mapped_rule_ids))
        rules_pct = round((rules_mapped / len(all_rules) * 100.0) if all_rules else 0.0, 2)

        # 4. Multi-rule techniques
        multi_rule_count = sum(1 for rules in tech_to_rules.values() if len(rules) > 1)

        # 5. Tactic breakdown
        tactics = db.query(AttackTacticModel).all()
        tactic_breakdown: List[TacticCoverageItem] = []

        for t in tactics:
            techs_in_t = db.query(AttackTechniqueModel).filter(
                (AttackTechniqueModel.tactic_id == t.tactic_id) |
                (AttackTechniqueModel.tactic_name == t.tactic_name)
            ).all()
            t_total = len(techs_in_t)
            t_ids = {x.technique_id for x in techs_in_t}

            t_mapped = len(t_ids.intersection(mapped_techs))
            t_ev = len(t_ids.intersection(evidence_backed_techs))

            t_map_pct = round((t_mapped / t_total * 100.0) if t_total > 0 else 0.0, 2)
            t_ev_pct = round((t_ev / t_total * 100.0) if t_total > 0 else 0.0, 2)

            tactic_breakdown.append(
                TacticCoverageItem(
                    tactic_id=t.tactic_id,
                    tactic_name=t.tactic_name,
                    total_techniques=t_total,
                    mapped_techniques=t_mapped,
                    evidence_backed_techniques=t_ev,
                    coverage_percentage=t_map_pct,
                    evidence_percentage=t_ev_pct,
                )
            )

        return AttackCoverageAnalyticsResponse(
            catalogue_version=meta.version,
            total_catalogue_techniques=total_techs,
            total_mapped_techniques=total_mapped,
            overall_mapping_coverage_pct=mapping_pct,
            total_evidence_backed_techniques=total_evidence,
            overall_evidence_coverage_pct=evidence_pct,
            detection_rules_total=len(all_rules),
            detection_rules_mapped=rules_mapped,
            detection_rules_coverage_pct=rules_pct,
            unmapped_rules=unmapped_rules,
            multi_rule_techniques_count=multi_rule_count,
            mappings_awaiting_review_count=pending_review_count,
            tactic_breakdown=tactic_breakdown,
        )

    @classmethod
    def get_traceability(cls, db: Session) -> AttackTraceabilityResponse:
        """Constructs end-to-end traceability paths from techniques through rules to live alerts and investigations."""
        cls.ensure_catalogue_initialized(db)

        registry_defs = mapping_registry.list_all_definitions(active_only=True)
        live_mappings = db.query(AttackDetectionMappingModel).all()

        traces: List[AttackTraceabilityItem] = []

        # 1. Trace from active definitions
        for d in registry_defs:
            tech = db.query(AttackTechniqueModel).filter(AttackTechniqueModel.technique_id == d.technique_id).first()
            rule = db.query(DetectionRuleModel).filter(DetectionRuleModel.rule_id == d.rule_id).first()

            # Find if there are live alerts for this rule and technique
            matching_lm = [lm for lm in live_mappings if lm.rule_id == d.rule_id and lm.technique_id == d.technique_id]

            if matching_lm:
                for lm in matching_lm:
                    alert = None
                    if lm.alert_id:
                        alert = db.query(AlertModel).filter(AlertModel.alert_id == lm.alert_id).first()

                    # Find investigation cluster membership
                    cluster_id = None
                    if alert:
                        cm = db.query(ClusterMembershipModel).filter(
                            (ClusterMembershipModel.member_id == str(alert.alert_id)) |
                            (ClusterMembershipModel.member_id == alert.source_address)
                        ).first()
                        if cm:
                            cluster_id = cm.cluster_id

                    traces.append(
                        AttackTraceabilityItem(
                            technique_id=d.technique_id,
                            technique_name=tech.technique_name if tech else d.technique_id,
                            tactic_name=tech.tactic_name if tech else "Discovery",
                            mapping_id=str(lm.mapping_id),
                            mapping_category=d.mapping_category.value if hasattr(d.mapping_category, "value") else str(d.mapping_category),
                            rule_id=d.rule_id,
                            rule_name=rule.rule_name if rule else d.rule_id,
                            rule_version=d.rule_version_range,
                            has_live_alert=alert is not None,
                            alert_id=str(alert.alert_id) if alert else None,
                            alert_severity=alert.severity if alert else None,
                            alert_confidence=alert.confidence if alert else None,
                            event_id=None,
                            session_id=None,
                            investigation_id=cluster_id,
                            navigation_url=f"/alerts?alert_id={alert.alert_id}" if alert else f"/mitre?technique_id={d.technique_id}",
                        )
                    )
            else:
                traces.append(
                    AttackTraceabilityItem(
                        technique_id=d.technique_id,
                        technique_name=tech.technique_name if tech else d.technique_id,
                        tactic_name=tech.tactic_name if tech else "Discovery",
                        mapping_id=d.mapping_definition_id,
                        mapping_category=d.mapping_category.value if hasattr(d.mapping_category, "value") else str(d.mapping_category),
                        rule_id=d.rule_id,
                        rule_name=rule.rule_name if rule else d.rule_id,
                        rule_version=d.rule_version_range,
                        has_live_alert=False,
                        navigation_url=f"/mitre?technique_id={d.technique_id}",
                    )
                )

        return AttackTraceabilityResponse(
            total_traces=len(traces),
            traces=traces,
        )

    @classmethod
    def review_mapping(
        cls,
        db: Session,
        mapping_id_str: str,
        req: MappingReviewActionRequest,
    ) -> Dict[str, Any]:
        """Applies human review decision (APPROVE, REJECT, REQUEST_REVIEW) to a mapping record."""
        try:
            m_uuid = uuid.UUID(mapping_id_str.strip())
            mapping = db.query(AttackDetectionMappingModel).filter(
                (AttackDetectionMappingModel.mapping_id == m_uuid) |
                (AttackDetectionMappingModel.id == m_uuid)
            ).first()
        except ValueError:
            mapping = None

        if not mapping:
            return {"error": f"Mapping '{mapping_id_str}' was not found in the database.", "status": 404}

        prev_status = mapping.review_status or "PENDING"

        # Action mapping
        if req.action == "APPROVE":
            action_code = "ACCEPT"
            new_status = "ACCEPTED"
        elif req.action == "REJECT":
            action_code = "REJECT"
            new_status = "REJECTED"
        else:
            action_code = "REQUEST_MORE_EVIDENCE"
            new_status = "PENDING"

        now_utc = datetime.now(timezone.utc)
        mapping.review_status = new_status
        mapping.review_comment = req.comment
        mapping.reviewed_by = req.analyst_id
        mapping.reviewed_at = now_utc

        # Record in AttackMappingReviewModel
        review_record = AttackMappingReviewModel(
            id=uuid.uuid4(),
            mapping_id=mapping.id,
            reviewer_id=req.analyst_id,
            review_action=action_code,
            previous_status=prev_status,
            new_status=new_status,
            review_comment=req.comment,
            reviewed_at=now_utc,
            created_at=now_utc,
        )
        db.add(review_record)

        # Record in AttackMappingHistoryModel
        history_record = AttackMappingHistoryModel(
            id=uuid.uuid4(),
            mapping_id=mapping.id,
            change_reason=f"Analyst {req.action}: {req.comment}",
            previous_confidence=mapping.mapping_confidence,
            new_confidence=mapping.mapping_confidence,
            previous_status=prev_status,
            new_status=new_status,
            policy_version="1.0",
            dataset_version=mapping.dataset_version or "v14.1",
        )
        db.add(history_record)

        db.commit()

        return {
            "mapping_id": str(mapping.mapping_id),
            "previous_status": prev_status,
            "new_status": new_status,
            "action": req.action,
            "reviewer_id": req.analyst_id,
            "reviewed_at": now_utc.isoformat(),
        }
