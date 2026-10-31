"""Pydantic request and response schemas for SnareSight MITRE ATT&CK integration."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ExternalReference(BaseModel):
    """External citation or web link to official ATT&CK resources."""
    source_name: str = Field(..., description="Source authority name, e.g. mitre-attack")
    external_id: Optional[str] = Field(None, description="Official external ID, e.g. T1110 or TA0006")
    url: Optional[str] = Field(None, description="Official reference URL")
    description: Optional[str] = Field(None, description="Reference description or citation")


class TacticSchema(BaseModel):
    """Adversary tactical objective schema."""
    stix_id: str
    tactic_id: str = Field(..., description="ATT&CK tactic ID (e.g. TA0001)")
    tactic_name: str
    short_name: str = Field(..., description="Lowercase identifier (e.g. credential-access)")
    description: Optional[str] = None
    dataset_version: str
    is_deprecated: bool = False
    is_revoked: bool = False
    external_references: List[ExternalReference] = []


class SubtechniqueSchema(BaseModel):
    """Specific technical manifestation of a parent technique."""
    stix_id: str
    subtechnique_id: str = Field(..., description="ATT&CK sub-technique ID (e.g. T1110.001)")
    subtechnique_name: str
    parent_technique_id: str = Field(..., description="Parent ATT&CK technique ID (e.g. T1110)")
    parent_stix_id: Optional[str] = None
    description: Optional[str] = None
    dataset_version: str
    platforms: List[str] = []
    is_deprecated: bool = False
    is_revoked: bool = False
    external_references: List[ExternalReference] = []


class TechniqueSchema(BaseModel):
    """Adversary technical procedure or attack pattern."""
    stix_id: Optional[str] = None
    technique_id: str = Field(..., description="ATT&CK technique ID (e.g. T1110)")
    technique_name: str
    tactic_id: str = Field(..., description="Primary tactic ID (e.g. TA0006)")
    tactic_name: str = Field(..., description="Primary tactic name")
    framework_version: str = "v14.1"
    description: Optional[str] = None
    is_subtechnique: bool = False
    tactics: List[str] = []
    platforms: List[str] = []
    data_sources: List[str] = []
    is_deprecated: bool = False
    is_revoked: bool = False
    external_references: List[ExternalReference] = []
    subtechniques: List[SubtechniqueSchema] = []


class RelationshipSchema(BaseModel):
    """STIX 2.1 relationship connecting ATT&CK entities."""
    stix_id: str
    relationship_type: str = Field(..., description="Relationship type, e.g. subtechnique-of")
    source_ref: str
    target_ref: str
    dataset_version: str
    description: Optional[str] = None
    is_deprecated: bool = False
    is_revoked: bool = False


class DatasetVersionResponse(BaseModel):
    """Metadata regarding an imported or candidate ATT&CK dataset version."""
    domain: str
    version: str
    stix_version: str
    source_repo: str
    source_filename: str
    retrieval_date: str
    release_date: Optional[str] = None
    sha256_checksum: str
    is_active: bool
    status: str
    object_count: int
    created_at: str


class CatalogueStatusResponse(BaseModel):
    """Operational health and summary status of the active ATT&CK catalogue."""
    catalogue_available: bool
    active_version: Optional[str] = None
    framework_domain: str = "enterprise-attack"
    last_import_at: Optional[str] = None
    health_status: str = "HEALTHY"
    total_tactics: int = 0
    total_techniques: int = 0
    total_subtechniques: int = 0
    total_relationships: int = 0


class DryRunPreviewResponse(BaseModel):
    """Preview summary generated prior to committing an external dataset."""
    dataset_domain: str
    dataset_version: str
    sha256_checksum: str
    total_objects: int
    tactics_discovered: int
    techniques_discovered: int
    subtechniques_discovered: int
    relationships_discovered: int
    unsupported_objects: int
    objects_to_add: int
    objects_to_update: int
    objects_to_deprecate_or_revoke: int
    validation_warnings: List[str] = []
    validation_errors: List[str] = []
    is_valid: bool = True


class ImportExecutionResponse(BaseModel):
    """Execution receipt for an approved dataset import."""
    import_run_id: str
    status: str
    dataset_version: str
    sha256_checksum: str
    total_parsed: int
    total_accepted: int
    total_rejected: int
    total_added: int
    total_updated: int
    total_unchanged: int
    total_deprecated: int
    total_revoked: int
    execution_duration_ms: float
    completed_at: str


class RollbackRequest(BaseModel):
    """Request payload to restore a previous active dataset version."""
    target_version: Optional[str] = None
    reason: str = Field("Manual administrative rollback", min_length=3, max_length=500)


class RollbackResponse(BaseModel):
    """Confirmation receipt for active dataset rollback."""
    previous_active_version: str
    current_active_version: str
    rollback_status: str
    reason: str
    rolled_back_at: str


class PaginatedTechniquesResponse(BaseModel):
    """Paginated collection of ATT&CK techniques."""
    total: int
    page: int
    page_size: int
    pages: int
    items: List[TechniqueSchema]

