"""Pydantic schemas for MITRE ATT&CK Threat Intelligence and Mapping Dashboard (Task P29)."""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


# --- Summary & Metadata ---

class AttackCatalogueMetadata(BaseModel):
    """Metadata describing the active MITRE ATT&CK catalogue release."""
    domain: str = Field(default="enterprise-attack")
    version: str = Field(default="v14.1")
    stix_version: str = Field(default="2.1")
    source_repo: str = Field(default="https://github.com/mitre-attack/attack-stix-data")
    sha256_checksum: Optional[str] = None
    retrieval_date: Optional[str] = None
    release_date: Optional[str] = None
    is_active: bool = True
    status: str = "ACTIVE"
    total_objects: int = 0
    mapping_registry_version: str = "v1.0"
    last_updated_at: str


class AttackDashboardSummary(BaseModel):
    """Aggregated KPIs for the MITRE ATT&CK dashboard header and summary cards."""
    total_catalogue_techniques: int
    total_catalogue_subtechniques: int
    total_catalogue_tactics: int
    techniques_mapped_to_detections: int
    techniques_with_alert_evidence: int
    techniques_pending_review: int
    detection_rules_mapped: int
    detection_rules_unmapped: int
    catalogue_metadata: AttackCatalogueMetadata
    last_refreshed_at: str


# --- Tactic Overview ---

class AttackTacticOverviewItem(BaseModel):
    """Summarized tactic metrics and SnareSight detection alignment."""
    tactic_id: str
    tactic_name: str
    short_name: str
    description: Optional[str] = None
    mapped_techniques_count: int
    supporting_rules_count: int
    related_alerts_count: int
    investigations_referencing_count: int


class AttackTacticOverviewResponse(BaseModel):
    """Collection of all Enterprise ATT&CK tactics with coverage counts."""
    total_tactics: int
    tactics: List[AttackTacticOverviewItem]


# --- Interactive Matrix ---

class AttackMatrixCell(BaseModel):
    """Single technique cell inside an ATT&CK matrix column."""
    technique_id: str
    technique_name: str
    is_subtechnique: bool
    parent_technique_id: Optional[str] = None
    mapping_status: str = Field(
        ...,
        description="UNMAPPED, RULE_MAPPED, ALERT_EVIDENCE, or REVIEW_REQUIRED",
    )
    mapped_rules: List[str] = Field(default_factory=list)
    alert_count: int = 0
    requires_review: bool = False
    confidence: Optional[int] = None
    subtechnique_count: int = 0


class AttackMatrixColumn(BaseModel):
    """Matrix column representing a single ATT&CK tactic and its techniques."""
    tactic_id: str
    tactic_name: str
    short_name: str
    techniques: List[AttackMatrixCell]


class AttackMatrixResponse(BaseModel):
    """Full Enterprise ATT&CK matrix columns and legend metadata."""
    domain: str
    version: str
    columns: List[AttackMatrixColumn]
    legend: Dict[str, str] = Field(
        default_factory=lambda: {
            "UNMAPPED": "No SnareSight detection mapping currently configured",
            "RULE_MAPPED": "Detection rule mapped, awaiting live honeypot trigger",
            "ALERT_EVIDENCE": "Corroborated by live honeypot security alert evidence",
            "REVIEW_REQUIRED": "Mapping requires analyst triage or review confirmation",
        }
    )
    non_attribution_notice: str = (
        "MITRE ATT&CK mappings indicate observed behavior consistent with adversary techniques. "
        "A mapped technique does not establish confirmed human identity, nation-state attribution, or production system compromise."
    )


# --- Technique Explorer ---

class AttackTechniqueExplorerItem(BaseModel):
    """Single row in the searchable technique explorer."""
    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    primary_tactic_id: Optional[str] = None
    primary_tactic_name: Optional[str] = None
    is_subtechnique: bool
    parent_technique_id: Optional[str] = None
    mapping_status: str
    visual_state: Optional[str] = None
    mapped_rules_count: int
    mapped_rules: List[str] = Field(default_factory=list)
    alert_evidence_count: int = 0
    supporting_alerts_count: int = 0
    platforms: List[str] = Field(default_factory=list)
    review_status: str
    confidence: Optional[int] = None


class AttackTechniqueExplorerResponse(BaseModel):
    """Paginated technique explorer search results."""
    total: int
    page: int
    page_size: int
    total_pages: int
    pages: int = 1
    items: List[AttackTechniqueExplorerItem]


# --- Technique Detail & Evidence ---

class AttackTechniqueMappingItem(BaseModel):
    """Specific detection rule mapping definition for a technique."""
    mapping_definition_id: str
    rule_id: str
    rule_name: Optional[str] = None
    rule_version: str
    mapping_category: str
    default_confidence: int
    mapping_rationale: str
    is_active: bool
    documentation_reference: Optional[str] = None


class AttackTechniqueEvidenceItem(BaseModel):
    """Supporting alert or event record linked to this technique."""
    evidence_id: str
    evidence_type: str
    record_id: str
    observed_at: Optional[str] = None
    supporting_rule_id: str
    source_ip: Optional[str] = None
    decoy_id: Optional[str] = None
    severity: Optional[str] = None
    confidence: Optional[int] = None
    navigation_url: str


class AttackTechniqueDetailResponse(BaseModel):
    """Comprehensive official and SnareSight context for a selected technique."""
    technique_id: str
    technique_name: str
    description: Optional[str] = None
    tactic_id: str
    tactic_name: str
    primary_tactic_id: Optional[str] = None
    primary_tactic_name: Optional[str] = None
    framework_version: str
    is_subtechnique: bool
    parent_technique_id: Optional[str] = None
    parent_technique_name: Optional[str] = None
    subtechniques: List[Dict[str, str]] = Field(default_factory=list)
    official_reference_url: Optional[str] = None
    tactics: List[Dict[str, str]] = Field(default_factory=list)
    platforms: List[str] = Field(default_factory=list)
    data_sources: List[str] = Field(default_factory=list)
    mapping_status: str
    visual_state: Optional[str] = None
    mappings: List[AttackTechniqueMappingItem] = Field(default_factory=list)
    configured_mappings: List[AttackTechniqueMappingItem] = Field(default_factory=list)
    supporting_evidence: List[AttackTechniqueEvidenceItem] = Field(default_factory=list)
    live_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    recent_reviews: List[Dict[str, Any]] = Field(default_factory=list)
    non_attribution_caveat: Optional[str] = None
    limitations: List[str] = Field(
        default_factory=lambda: [
            "Observed activity occurred within an isolated deception honeypot environment.",
            "Mapping indicates observed behavior consistent with the technique; it does NOT confirm production breach.",
            "Technique mapping does not infer attacker nation-state attribution, physical identity, or operational skill.",
            "Absence of a mapping does not prove absence of threat activity.",
        ]
    )


# --- Coverage Analytics ---

class TacticCoverageItem(BaseModel):
    """Coverage percentages for a single ATT&CK tactic."""
    tactic_id: str
    tactic_name: str
    total_techniques: int
    mapped_techniques: int
    evidence_backed_techniques: int
    coverage_percentage: float
    evidence_percentage: float


class AttackCoverageAnalyticsResponse(BaseModel):
    """Enterprise-wide detection mapping coverage metrics and tactic breakdowns."""
    catalogue_version: str
    total_catalogue_techniques: int
    total_mapped_techniques: int
    overall_mapping_coverage_pct: float
    total_evidence_backed_techniques: int
    overall_evidence_coverage_pct: float
    detection_rules_total: int
    detection_rules_mapped: int
    detection_rules_coverage_pct: float
    unmapped_rules: List[str]
    multi_rule_techniques_count: int
    mappings_awaiting_review_count: int
    tactic_breakdown: List[TacticCoverageItem]


# --- Traceability ---

class AttackTraceabilityItem(BaseModel):
    """End-to-end evidence trace for an active technique mapping."""
    technique_id: str
    technique_name: str
    tactic_name: str
    mapping_id: Optional[str] = None
    mapping_category: str
    rule_id: str
    rule_name: str
    rule_version: str
    has_live_alert: bool
    alert_id: Optional[str] = None
    alert_severity: Optional[str] = None
    alert_confidence: Optional[int] = None
    event_id: Optional[str] = None
    session_id: Optional[str] = None
    investigation_id: Optional[str] = None
    navigation_url: str


class AttackTraceabilityResponse(BaseModel):
    """Complete traceability chains connecting techniques to observed incidents."""
    total_traces: int
    traces: List[AttackTraceabilityItem]


# --- Review Actions ---

class MappingReviewActionRequest(BaseModel):
    """Analyst review submission for an ATT&CK mapping."""
    analyst_id: str = Field(..., min_length=1, description="Identifier of the reviewing analyst")
    action: str = Field(
        ...,
        pattern="^(APPROVE|REJECT|REQUEST_REVIEW)$",
        description="Review decision: APPROVE, REJECT, or REQUEST_REVIEW",
    )
    comment: str = Field(..., min_length=3, description="Justification or evidence commentary")

