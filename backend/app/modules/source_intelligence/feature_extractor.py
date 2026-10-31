"""Behavioral feature extraction from honeypot telemetry and correlated sessions."""

from datetime import datetime, timezone
from collections import defaultdict
from typing import Any, Sequence
from app.db.models.event import SecurityEventModel
from app.db.models.correlation import ActivitySessionModel
from app.db.models.alert import AlertModel


TRAVERSAL_INDICATORS = (
    "..",
    "%2e%2e",
    "..%2f",
    "%2e%2e%2f",
    "/etc/passwd",
    "/etc/shadow",
    "cmd.exe",
    "powershell",
    "/bin/sh",
    "/bin/bash",
    "boot.ini",
    "win.ini",
)


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _get_event_timestamp(ev: SecurityEventModel) -> datetime | None:
    return getattr(ev, "observed_at", getattr(ev, "timestamp", None))


def _get_session_start(s: ActivitySessionModel) -> datetime | None:
    return getattr(s, "first_observed_at", getattr(s, "start_time", None))


def _get_session_end(s: ActivitySessionModel) -> datetime | None:
    return (
        getattr(s, "ended_at", None)
        or getattr(s, "last_activity_at", None)
        or getattr(s, "end_time", None)
        or _get_session_start(s)
    )


def extract_features_from_records(
    events: Sequence[SecurityEventModel],
    sessions: Sequence[ActivitySessionModel],
    alerts: Sequence[AlertModel],
    window_type: str = "ALL_TIME",
    window_start: datetime | None = None,
    window_end: datetime | None = None,
) -> dict[str, Any]:
    """Computes comprehensive behavioral feature metrics for an observed source.
    
    Zero-Password Persistence Invariant: Passwords, credentials, or secret tokens
    are NEVER inspected, persisted, or aggregated. Only username counts, path counts,
    and frequency distributions are extracted.
    """
    total_events = len(events)
    total_sessions = len(sessions)

    # 1. Interaction Tempo & Burstiness
    if total_events > 0:
        event_times = sorted([_ensure_utc(_get_event_timestamp(e)) for e in events if _get_event_timestamp(e)])
        if len(event_times) >= 2:
            span_seconds = max((event_times[-1] - event_times[0]).total_seconds(), 1.0)
            span_minutes = max(span_seconds / 60.0, 1.0)
            interaction_tempo = round(total_events / span_minutes, 2)
        else:
            interaction_tempo = float(total_events)

        # 1-minute bucket distribution for burstiness
        minute_buckets: dict[str, int] = defaultdict(int)
        for t in event_times:
            if t:
                bucket_key = t.strftime("%Y-%m-%d %H:%M")
                minute_buckets[bucket_key] += 1
        
        peak_rate = max(minute_buckets.values()) if minute_buckets else total_events
        avg_rate = total_events / max(len(minute_buckets), 1)
        burstiness_ratio = round(peak_rate / max(avg_rate, 1.0), 2)
    else:
        interaction_tempo = 0.0
        burstiness_ratio = 0.0

    # 2. Concurrency Level (Max overlapping sessions)
    concurrency_level = 1
    if total_sessions > 1:
        session_intervals = [
            (_ensure_utc(_get_session_start(s)), _ensure_utc(_get_session_end(s)))
            for s in sessions
            if _get_session_start(s)
        ]
        active_counts = []
        for start, end in session_intervals:
            if start and end:
                overlapping = sum(1 for s_start, s_end in session_intervals if s_start and s_end and s_start <= start <= s_end)
                active_counts.append(overlapping)
        concurrency_level = max(active_counts) if active_counts else 1

    # 3. Authentication Exploration Features
    auth_attempt_count = 0
    auth_failure_count = 0
    distinct_usernames = set()

    # 4. Traversal & Path Probing Features
    path_traversal_probes = 0
    distinct_paths = set()
    distinct_honeypots = set()

    for ev in events:
        decoy_id = getattr(ev, "decoy_id", None) or getattr(ev, "honeypot_id", None)
        if decoy_id:
            distinct_honeypots.add(str(decoy_id))

        cat = (getattr(ev, "event_category", "") or "").upper()
        etype = (getattr(ev, "event_type", "") or "").upper()
        outcome = (getattr(ev, "outcome", "") or "").upper()

        if "AUTH" in cat or "LOGIN" in etype or "SSH" in etype:
            auth_attempt_count += 1
            if outcome in ("FAILURE", "FAILED", "BLOCKED", "DENIED", "REJECTED"):
                auth_failure_count += 1

        details = getattr(ev, "sanitized_metadata", None) or getattr(ev, "event_details", {}) or {}
        # Username observation (never passwords)
        user = details.get("username") or details.get("user") or details.get("auth_username")
        if user and isinstance(user, str) and user.strip():
            distinct_usernames.add(user.strip())

        # Path exploration
        path = details.get("path") or details.get("url") or details.get("uri") or details.get("command")
        if path and isinstance(path, str):
            clean_path = path.strip()
            distinct_paths.add(clean_path)
            lower_path = clean_path.lower()
            if any(ind in lower_path for ind in TRAVERSAL_INDICATORS):
                path_traversal_probes += 1

    # 5. MITRE Tactic and Technique Distributions
    tactic_distribution: dict[str, int] = defaultdict(int)
    technique_distribution: dict[str, int] = defaultdict(int)

    for alert in alerts:
        tac = getattr(alert, "mitre_tactic", None) or (getattr(alert, "recommendations", {}) or {}).get("mitre_tactic")
        if tac:
            tactic_distribution[str(tac).upper()] += 1
        tech = getattr(alert, "mitre_technique_id", None) or (getattr(alert, "recommendations", {}) or {}).get("mitre_technique_id")
        if tech:
            technique_distribution[str(tech).upper()] += 1

    # 6. Severity Breakdown
    severity_breakdown: dict[str, int] = defaultdict(int)
    for alert in alerts:
        sev = (getattr(alert, "severity", "MEDIUM") or "MEDIUM").upper()
        severity_breakdown[sev] += 1

    return {
        "window_type": window_type,
        "window_start": window_start,
        "window_end": window_end,
        "interaction_tempo": interaction_tempo,
        "burstiness_ratio": burstiness_ratio,
        "concurrency_level": concurrency_level,
        "auth_attempt_count": auth_attempt_count,
        "auth_failure_count": auth_failure_count,
        "distinct_usernames_count": len(distinct_usernames),
        "path_traversal_probes": path_traversal_probes,
        "distinct_paths_probed": len(distinct_paths),
        "distinct_honeypots_targeted": len(distinct_honeypots),
        "tactic_distribution": dict(tactic_distribution),
        "technique_distribution": dict(technique_distribution),
        "severity_breakdown": dict(severity_breakdown),
        "calculated_at": datetime.now(timezone.utc),
    }
