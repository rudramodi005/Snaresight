"""SnareSight Event Correlation Subsystem (Task P21)."""

from app.correlation.exceptions import (
    CorrelationError,
    SessionNotFoundError,
    CorrelationPolicyError,
    InvalidSessionStateError,
    DuplicateAssociationError,
)
from app.correlation.schemas import (
    SessionStatus,
    CorrelationMethod,
    TimelineEntryType,
    ActivitySessionSummary,
    ActivitySessionResponse,
    PaginatedSessionsResponse,
    TimelineEntryResponse,
    SessionTimelineResponse,
    SessionEventResponse,
    SessionStatisticsResponse,
)
from app.correlation.policy import CorrelationPolicy, default_correlation_policy
from app.correlation.identity import SessionIdentity, SessionIdentityResolver
from app.correlation.engine import CorrelationEngine, correlation_engine
from app.correlation.timeline import InvestigationTimelineBuilder
from app.correlation.service import CorrelationService
from app.correlation.routes import router as correlation_router
from app.modules.correlation.sequence_engine import SequenceEngine, default_sequence_engine
from app.modules.correlation.sequence_service import SequenceService
from app.modules.correlation.sequence_routes import router as sequence_router

__all__ = [
    "CorrelationError",
    "SessionNotFoundError",
    "CorrelationPolicyError",
    "InvalidSessionStateError",
    "DuplicateAssociationError",
    "SessionStatus",
    "CorrelationMethod",
    "TimelineEntryType",
    "ActivitySessionSummary",
    "ActivitySessionResponse",
    "PaginatedSessionsResponse",
    "TimelineEntryResponse",
    "SessionTimelineResponse",
    "SessionEventResponse",
    "SessionStatisticsResponse",
    "CorrelationPolicy",
    "default_correlation_policy",
    "SessionIdentity",
    "SessionIdentityResolver",
    "CorrelationEngine",
    "correlation_engine",
    "InvestigationTimelineBuilder",
    "CorrelationService",
    "correlation_router",
    "SequenceEngine",
    "default_sequence_engine",
    "SequenceService",
    "sequence_router",
]
