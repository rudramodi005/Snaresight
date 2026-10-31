"""Role-based access control (RBAC) permission definitions and matrix.

Defines roles (ADMIN, ANALYST, VIEWER) and the explicit 17 security permissions
enforced across the SnareSight platform.
"""

from enum import Enum
from typing import Set, Dict


class Role(str, Enum):
    """System security roles."""
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"


class Permission(str, Enum):
    """Atomic permissions required for operational capabilities."""
    VIEW_DASHBOARD = "view_dashboard"
    VIEW_EVENTS = "view_events"
    VIEW_SENSITIVE_EVIDENCE = "view_sensitive_evidence"
    VIEW_ALERTS = "view_alerts"
    ASSIGN_ALERTS = "assign_alerts"
    ACKNOWLEDGE_ALERTS = "acknowledge_alerts"
    RESOLVE_ALERTS = "resolve_alerts"
    CLOSE_ALERTS = "close_alerts"
    ADD_INVESTIGATION_NOTES = "add_investigation_notes"
    MODIFY_MAPPING_REVIEW_STATUS = "modify_mapping_review_status"
    GENERATE_REPORTS = "generate_reports"
    EXPORT_DATA = "export_data"
    MANAGE_SENSORS = "manage_sensors"
    MANAGE_DETECTION_RULES = "manage_detection_rules"
    MANAGE_USERS = "manage_users"
    VIEW_AUDIT_LOGS = "view_audit_logs"
    MODIFY_SYSTEM_CONFIGURATION = "modify_system_configuration"


# Role-to-Permissions Mapping Matrix
ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.ADMIN: {
        Permission.VIEW_DASHBOARD,
        Permission.VIEW_EVENTS,
        Permission.VIEW_SENSITIVE_EVIDENCE,
        Permission.VIEW_ALERTS,
        Permission.ASSIGN_ALERTS,
        Permission.ACKNOWLEDGE_ALERTS,
        Permission.RESOLVE_ALERTS,
        Permission.CLOSE_ALERTS,
        Permission.ADD_INVESTIGATION_NOTES,
        Permission.MODIFY_MAPPING_REVIEW_STATUS,
        Permission.GENERATE_REPORTS,
        Permission.EXPORT_DATA,
        Permission.MANAGE_SENSORS,
        Permission.MANAGE_DETECTION_RULES,
        Permission.MANAGE_USERS,
        Permission.VIEW_AUDIT_LOGS,
        Permission.MODIFY_SYSTEM_CONFIGURATION,
    },
    Role.ANALYST: {
        Permission.VIEW_DASHBOARD,
        Permission.VIEW_EVENTS,
        Permission.VIEW_SENSITIVE_EVIDENCE,
        Permission.VIEW_ALERTS,
        Permission.ASSIGN_ALERTS,
        Permission.ACKNOWLEDGE_ALERTS,
        Permission.RESOLVE_ALERTS,
        Permission.CLOSE_ALERTS,
        Permission.ADD_INVESTIGATION_NOTES,
        Permission.MODIFY_MAPPING_REVIEW_STATUS,
        Permission.GENERATE_REPORTS,
        Permission.EXPORT_DATA,
        Permission.VIEW_AUDIT_LOGS,
    },
    Role.VIEWER: {
        Permission.VIEW_DASHBOARD,
        Permission.VIEW_EVENTS,
        Permission.VIEW_ALERTS,
    },
}


def has_permission(role: str, permission: Permission | str) -> bool:
    """Evaluates whether a role possesses a specific permission."""
    try:
        r = Role(role.upper())
    except ValueError:
        return False

    perm = Permission(permission) if isinstance(permission, str) else permission
    return perm in ROLE_PERMISSIONS.get(r, set())

