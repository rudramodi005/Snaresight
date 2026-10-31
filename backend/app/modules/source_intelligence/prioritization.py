"""Explainable profile prioritization model for Observed Source Profiles."""

from typing import Any, Tuple


def evaluate_profile_priority(
    total_events: int,
    total_sessions: int,
    total_alerts: int,
    distinct_honeypots: int,
    features: dict[str, Any],
) -> Tuple[str, str]:
    """Evaluates an explainable priority tier for an Observed Source Profile.
    
    Guiding Principles:
    - Independent of subjective assumptions; grounded strictly in observed metrics.
    - Does NOT infer physical human identity or threat group attribution.
    - Returns (priority_tier, explainable_rationale).
    
    Tiers:
    - INSUFFICIENT_DATA
    - LOW
    - MEDIUM
    - HIGH
    - CRITICAL
    """
    if total_events < 2 or total_sessions == 0:
        return (
            "INSUFFICIENT_DATA",
            "Observed activity is too sparse (< 2 events or 0 correlated sessions) to establish a behavioral baseline.",
        )

    severity_breakdown = features.get("severity_breakdown", {})
    critical_alerts = severity_breakdown.get("CRITICAL", 0)
    high_alerts = severity_breakdown.get("HIGH", 0)
    auth_failures = features.get("auth_failure_count", 0)
    traversal_probes = features.get("path_traversal_probes", 0)
    distinct_users = features.get("distinct_usernames_count", 0)
    tempo = features.get("interaction_tempo", 0.0)

    # CRITICAL Priority Assessment
    if critical_alerts >= 1:
        return (
            "CRITICAL",
            f"Observed source triggered {critical_alerts} CRITICAL alert(s) across deception endpoints.",
        )
    if high_alerts >= 2 and distinct_honeypots >= 2:
        return (
            "CRITICAL",
            f"Multi-decoy targeting across {distinct_honeypots} honeypots with {high_alerts} HIGH-severity security alerts.",
        )
    if auth_failures >= 30 and traversal_probes >= 5:
        return (
            "CRITICAL",
            f"High-velocity combined credential spray ({auth_failures} failures) and directory traversal probes ({traversal_probes} probes).",
        )

    # HIGH Priority Assessment
    if high_alerts >= 1:
        return (
            "HIGH",
            f"Observed source triggered {high_alerts} HIGH-severity alert(s) in active sessions.",
        )
    if distinct_honeypots >= 3:
        return (
            "HIGH",
            f"Broad reconnaissance observed spanning {distinct_honeypots} distinct honeypot decoys.",
        )
    if auth_failures >= 10 or distinct_users >= 5:
        return (
            "HIGH",
            f"Credential spraying behavior observed: {auth_failures} failed attempts across {distinct_users} distinct usernames.",
        )
    if traversal_probes >= 3:
        return (
            "HIGH",
            f"Repeated path traversal / command execution probes detected ({traversal_probes} attempts).",
        )

    # MEDIUM Priority Assessment
    if total_alerts > 0:
        return (
            "MEDIUM",
            f"Observed source triggered {total_alerts} security alert(s) with confirmed detection rules.",
        )
    if total_sessions >= 3 or total_events >= 20:
        return (
            "MEDIUM",
            f"Persistent multi-session probing across {total_sessions} sessions with {total_events} observed events.",
        )
    if traversal_probes >= 1 or distinct_users >= 2:
        return (
            "MEDIUM",
            "Targeted path probing or multi-username inquiry observed without high-severity triggers.",
        )

    # LOW Priority Assessment
    return (
        "LOW",
        f"Low-volume interaction ({total_events} events, {total_sessions} session(s)) with no elevated detection alerts.",
    )

