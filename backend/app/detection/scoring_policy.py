"""Declarative scoring policy models and centralized registry for SnareSight.

Governs severity classification, confidence calculation weights, evidence strength
thresholds, and provenance handling rules.
"""

from enum import Enum
from typing import Dict, List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field, model_validator
from app.detection.exceptions import InvalidPolicyError, ScoringPolicyError


class SeverityLevel(str, Enum):
    """Five-tier categorical threat severity."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ConfidenceLevel(str, Enum):
    """Five-tier evidence confidence rating."""
    VERY_LOW = "VERY_LOW"
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    VERY_HIGH = "VERY_HIGH"


class EvidenceStrength(str, Enum):
    """Four-tier evidence reliability and completeness classification."""
    INSUFFICIENT = "INSUFFICIENT"
    LIMITED = "LIMITED"
    MODERATE = "MODERATE"
    STRONG = "STRONG"


class ProvenanceType(str, Enum):
    """Standardized event provenance classification."""
    LIVE_HONEYPOT = "LIVE_HONEYPOT"
    CONTROLLED_TEST = "CONTROLLED_TEST"
    SYNTHETIC_SIMULATION = "SYNTHETIC_SIMULATION"
    IMPORTED_DATA = "IMPORTED_DATA"


class ConfidenceWeights(BaseModel):
    """Configurable weights for confidence scoring components (must sum to 1.0)."""
    rule_match_quality: float = Field(0.25, ge=0.0, le=1.0)
    event_validity: float = Field(0.20, ge=0.0, le=1.0)
    source_reliability: float = Field(0.15, ge=0.0, le=1.0)
    provenance_fidelity: float = Field(0.15, ge=0.0, le=1.0)
    session_consistency: float = Field(0.15, ge=0.0, le=1.0)
    timestamp_quality: float = Field(0.10, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def validate_sum(self):
        total = (
            self.rule_match_quality
            + self.event_validity
            + self.source_reliability
            + self.provenance_fidelity
            + self.session_consistency
            + self.timestamp_quality
        )
        if round(total, 4) != 1.0000:
            raise ValueError(f"Confidence weights must sum exactly to 1.0, got {total}")
        return self


class ScoringPolicyDefinition(BaseModel):
    """Complete declarative specification of a SnareSight scoring policy."""
    policy_id: str = Field(..., min_length=3, max_length=64)
    policy_version: str = Field("1.0", min_length=1, max_length=16)
    policy_name: str = Field(..., min_length=3, max_length=128)
    description: str = Field(..., min_length=5, max_length=2000)
    enabled: bool = Field(default=True)
    confidence_weights: ConfidenceWeights = Field(default_factory=ConfidenceWeights)
    
    # Documented evidence penalties deducted from base score
    penalties: Dict[str, float] = Field(
        default_factory=lambda: {
            "invalid_timestamp": 30.0,
            "contradictory_evidence": 25.0,
            "missing_session_context": 15.0,
            "unverified_source": 20.0,
            "synthetic_provenance_flag": 0.0,  # Synthetic does not penalize calculation, but labels outcome
        }
    )

    # Score-to-tier mappings for confidence
    confidence_tier_boundaries: Dict[str, int] = Field(
        default_factory=lambda: {
            "VERY_LOW": 0,
            "LOW": 20,
            "MODERATE": 40,
            "HIGH": 60,
            "VERY_HIGH": 80,
        }
    )

    # Policy control: CRITICAL severity requires multi-criteria justification
    allow_critical_auto_escalation: bool = Field(default=False)
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    created_by: Optional[str] = "system"
    approved_by: Optional[str] = None


class ScoringPolicyRegistry:
    """Thread-safe, version-aware registry of scoring policies."""

    def __init__(self):
        # Structure: {policy_id: {version: ScoringPolicyDefinition}}
        self._policies: Dict[str, Dict[str, ScoringPolicyDefinition]] = {}
        self._active_versions: Dict[str, str] = {}
        # Register standard default policy
        self._initialize_default_policy()

    def _initialize_default_policy(self) -> None:
        """Seeds the standard default policy."""
        default_policy = ScoringPolicyDefinition(
            policy_id="DEFAULT_SCORING_POLICY",
            policy_version="1.0",
            policy_name="Standard Deception Threat Assessment Policy",
            description="Baseline evidence-based scoring policy for SnareSight honeypot observations.",
            enabled=True,
            created_at=datetime.now(timezone.utc).isoformat(),
            updated_at=datetime.now(timezone.utc).isoformat(),
            created_by="system",
        )
        self.register_policy(default_policy, validate=True)

    def register_policy(
        self,
        policy: ScoringPolicyDefinition | dict,
        validate: bool = True,
    ) -> ScoringPolicyDefinition:
        """Validates and registers an immutable scoring policy version."""
        policy_obj = policy if isinstance(policy, ScoringPolicyDefinition) else ScoringPolicyDefinition.model_validate(policy)
        
        pid = policy_obj.policy_id
        ver = policy_obj.policy_version

        if pid not in self._policies:
            self._policies[pid] = {}

        if ver in self._policies[pid]:
            raise InvalidPolicyError(f"Scoring policy '{pid}' version '{ver}' is already registered and immutable.")

        self._policies[pid][ver] = policy_obj
        self._active_versions[pid] = ver
        return policy_obj

    def get_policy(self, policy_id: str = "DEFAULT_SCORING_POLICY", version: Optional[str] = None) -> ScoringPolicyDefinition:
        """Retrieves a specific policy version or current active version."""
        if policy_id not in self._policies:
            raise ScoringPolicyError(f"Scoring policy '{policy_id}' not found")

        versions = self._policies[policy_id]
        target_ver = version or self._active_versions.get(policy_id)
        if not target_ver or target_ver not in versions:
            raise ScoringPolicyError(f"Version '{target_ver}' of scoring policy '{policy_id}' not found")

        return versions[target_ver]

    def get_versions(self, policy_id: str) -> List[str]:
        """Lists all registered version strings for a policy ID."""
        if policy_id not in self._policies:
            raise ScoringPolicyError(f"Scoring policy '{policy_id}' not found")
        return sorted(list(self._policies[policy_id].keys()))

    def list_policies(self) -> List[ScoringPolicyDefinition]:
        """Lists current active version of all registered scoring policies."""
        return [self._policies[pid][ver] for pid, ver in self._active_versions.items()]

    def clear(self) -> None:
        """Clears registry for test isolation."""
        self._policies.clear()
        self._active_versions.clear()
        self._initialize_default_policy()


# Module-level default singleton registry
scoring_policy_registry = ScoringPolicyRegistry()

