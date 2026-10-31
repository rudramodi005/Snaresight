"""Schema and taxonomy registry for SnareSight event normalization.

Maintains canonical schema contracts, supported event types, categories, and actions.
"""

from typing import Set


class SchemaRegistry:
    """Central registry for supported schema versions, categories, and event types."""

    SUPPORTED_SCHEMA_VERSIONS: Set[str] = {"1.0"}

    # Supported P11 Taxonomy Categories
    CATEGORIES: Set[str] = {
        "CONNECTION",
        "REQUEST",
        "AUTHENTICATION",
        "SESSION",
        "COMMAND_INTERACTION",
        "FILE_INTERACTION",
        "SERVICE_HEALTH",
        "SECURITY_OBSERVATION",
        "SIMULATION",
    }

    # Supported P11 Canonical Actions
    ACTIONS: Set[str] = {
        "HTTP_GET",
        "HTTP_POST",
        "HTTP_REQUEST",
        "SUBMIT_CREDENTIALS",
        "PORTAL_NAVIGATION",
        "MALFORMED_PROBE",
        "SESSION_INITIATE",
        "SESSION_TERMINATE",
        "COMMAND_EXECUTE",
        "FILE_UPLOAD",
        "FILE_DOWNLOAD",
        "PORT_SCAN",
        "SERVICE_HEARTBEAT",
    }

    # Supported Outcomes
    OUTCOMES: Set[str] = {
        "SUCCESS",
        "FAILURE",
        "BLOCKED",
        "ERROR",
        "UNKNOWN",
    }

    # Supported Provenance tokens
    PROVENANCE_TOKENS: Set[str] = {
        "LIVE_HONEYPOT",
        "CONTROLLED_TEST",
        "SYNTHETIC_SIMULATION",
        "IMPORTED_DATA",
        "real_attacker",
        "internal_test",
        "controlled_test",
        "synthetic_simulation",
        "automated_scan",
        "research",
    }

    @classmethod
    def is_supported_version(cls, version: str) -> bool:
        """Checks if a schema version string is supported."""
        return version in cls.SUPPORTED_SCHEMA_VERSIONS

    @classmethod
    def is_valid_category(cls, category: str) -> bool:
        """Checks if an event category is in the approved taxonomy."""
        return category.upper() in cls.CATEGORIES

    @classmethod
    def is_valid_action(cls, action: str) -> bool:
        """Checks if an action is supported."""
        return action.upper() in cls.ACTIONS

    @classmethod
    def is_valid_outcome(cls, outcome: str) -> bool:
        """Checks if an outcome is in the approved enumeration."""
        return outcome.upper() in cls.OUTCOMES

