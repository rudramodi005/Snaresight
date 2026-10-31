"""Status enumerations and classification standards for SnareSight pipeline health."""

from enum import Enum


class ComponentHealthStatus(str, Enum):
    """Operational health classification for individual components."""
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"
    UNKNOWN = "UNKNOWN"
    NOT_CONFIGURED = "NOT_CONFIGURED"


class PipelineOverallStatus(str, Enum):
    """Aggregate pipeline health classification."""
    OPERATIONAL = "OPERATIONAL"
    DEGRADED = "DEGRADED"
    DOWN = "DOWN"
    UNKNOWN = "UNKNOWN"

