"""SnareSight Source Intelligence Subsystem (Task P23).

Multi-session source profiling, behavioral intelligence, similarity analysis,
recurrence detection, and explainable prioritization.
"""

from app.modules.source_intelligence.schemas import (
    SourceProfileResponse,
    SourceProfileListResponse,
    FeatureMetricsResponse,
    ProfileBehaviorResponse,
    ProfileTrendsResponse,
    SimilarProfileResponse,
    RecurrenceResponse,
    HistoryResponse,
)
from app.modules.source_intelligence.fingerprint import (
    canonicalize_ip,
    generate_source_fingerprint,
    generate_profile_id,
    format_source_display_label,
)
from app.modules.source_intelligence.feature_extractor import extract_features_from_records
from app.modules.source_intelligence.prioritization import evaluate_profile_priority
from app.modules.source_intelligence.similarity import compare_source_profiles
from app.modules.source_intelligence.recurrence import detect_profile_recurrences
from app.modules.source_intelligence.aggregator import SourceProfileAggregator
from app.modules.source_intelligence.service import SourceIntelligenceService
from app.modules.source_intelligence.routes import router

__all__ = [
    "SourceProfileResponse",
    "SourceProfileListResponse",
    "FeatureMetricsResponse",
    "ProfileBehaviorResponse",
    "ProfileTrendsResponse",
    "SimilarProfileResponse",
    "RecurrenceResponse",
    "HistoryResponse",
    "canonicalize_ip",
    "generate_source_fingerprint",
    "generate_profile_id",
    "format_source_display_label",
    "extract_features_from_records",
    "evaluate_profile_priority",
    "compare_source_profiles",
    "detect_profile_recurrences",
    "SourceProfileAggregator",
    "SourceIntelligenceService",
    "router",
]

