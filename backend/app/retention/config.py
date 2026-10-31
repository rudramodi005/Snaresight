"""Centralized retention policy configuration for SnareSight.

Defines configurable data retention windows, validation bounds,
and policy version tracking.
"""

import os
from typing import Dict, Any


class RetentionPolicyConfig:
    """Centralized retention configuration with bounded policy enforcement."""

    POLICY_VERSION = "1.0"

    # Default retention periods in days (Provisional settings subject to admin approval)
    DEFAULT_RETENTION_DAYS: Dict[str, int] = {
        "RAW_EVENTS": 90,
        "NORMALIZED_EVENTS": 180,
        "ALERTS": 365,
        "SIMULATION_EVENTS": 14,
        "IMPORT_HISTORY": 30,
        "OPERATIONAL_LOGS": 30,
        "AUDIT_RECORDS": 730,
        "INVESTIGATION_EVIDENCE": 1095,
    }

    # Minimum and Maximum allowed values in days
    BOUNDS: Dict[str, tuple[int, int]] = {
        "RAW_EVENTS": (7, 730),
        "NORMALIZED_EVENTS": (14, 1095),
        "ALERTS": (30, 2555),
        "SIMULATION_EVENTS": (1, 90),
        "IMPORT_HISTORY": (7, 180),
        "OPERATIONAL_LOGS": (3, 90),
        "AUDIT_RECORDS": (90, 3650),
        "INVESTIGATION_EVIDENCE": (180, 3650),
    }

    def __init__(self, overrides: Dict[str, int] | None = None) -> None:
        self._policies: Dict[str, int] = dict(self.DEFAULT_RETENTION_DAYS)
        if overrides:
            for cat, days in overrides.items():
                self.set_retention(cat, days)

    def get_retention_days(self, category: str) -> int:
        """Retrieves retention duration in days for a category."""
        cat_upper = category.upper()
        if cat_upper not in self._policies:
            raise ValueError(f"Unknown data retention category: '{category}'")
        return self._policies[cat_upper]

    def set_retention(self, category: str, days: int) -> None:
        """Updates retention duration while enforcing safety bounds."""
        cat_upper = category.upper()
        if cat_upper not in self.BOUNDS:
            raise ValueError(f"Cannot configure retention for unknown category: '{category}'")
        min_allowed, max_allowed = self.BOUNDS[cat_upper]
        if not (min_allowed <= days <= max_allowed):
            raise ValueError(
                f"Retention duration {days} days for '{category}' violates bounds [{min_allowed}, {max_allowed}]"
            )
        self._policies[cat_upper] = days

    def get_all_policies(self) -> Dict[str, int]:
        """Returns read-only copy of active retention policies."""
        return dict(self._policies)


# Default singleton instance
retention_config = RetentionPolicyConfig()

