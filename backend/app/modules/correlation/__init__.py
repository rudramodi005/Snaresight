"""SnareSight Behavioral Sequences & Multi-Session Correlation Module (Task P22)."""

from app.modules.correlation.sequence_engine import SequenceEngine, default_sequence_engine
from app.modules.correlation.sequence_policy import CrossSessionCorrelationPolicy, default_sequence_policy
from app.modules.correlation.sequence_scoring import SequenceScorer
from app.modules.correlation.sequence_service import SequenceService
from app.modules.correlation.sequence_routes import router as sequence_router

__all__ = [
    "SequenceEngine",
    "default_sequence_engine",
    "CrossSessionCorrelationPolicy",
    "default_sequence_policy",
    "SequenceScorer",
    "SequenceService",
    "sequence_router",
]

