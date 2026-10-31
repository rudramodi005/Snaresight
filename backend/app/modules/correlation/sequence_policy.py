"""Cross-Session Behavioral Correlation Policy and Pattern Definitions (Task P22)."""

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple
from app.modules.correlation.sequence_schemas import SequencePatternType


class CrossSessionCorrelationPolicy:
    """Configurable policy parameters and behavioral pattern evaluation rules."""

    DEFAULT_POLICY_VERSION = "1.0"
    DEFAULT_MAX_CORRELATION_WINDOW_SECONDS = 86400  # 24 hours between adjacent sessions
    DEFAULT_MAX_SEQUENCE_SPAN_SECONDS = 604800  # 7 days max total sequence duration
    DEFAULT_MIN_SESSIONS = 2

    def __init__(
        self,
        policy_version: str = DEFAULT_POLICY_VERSION,
        max_correlation_window_seconds: int = DEFAULT_MAX_CORRELATION_WINDOW_SECONDS,
        max_sequence_span_seconds: int = DEFAULT_MAX_SEQUENCE_SPAN_SECONDS,
        min_sessions: int = DEFAULT_MIN_SESSIONS,
    ):
        self.policy_version = policy_version
        self.max_correlation_window_seconds = max_correlation_window_seconds
        self.max_sequence_span_seconds = max_sequence_span_seconds
        self.min_sessions = min_sessions
        # Strict security invariant: IP alone is NEVER allowed to establish sequence correlation
        self.ip_alone_correlation_allowed = False

    def is_within_temporal_window(
        self,
        session_a_time: datetime,
        session_b_time: datetime,
        sequence_start_time: Optional[datetime] = None,
    ) -> Tuple[bool, str]:
        """Validates that candidate sessions fall within acceptable temporal windows."""
        a_utc = session_a_time if session_a_time.tzinfo else session_a_time.replace(tzinfo=timezone.utc)
        b_utc = session_b_time if session_b_time.tzinfo else session_b_time.replace(tzinfo=timezone.utc)

        gap = abs((b_utc - a_utc).total_seconds())
        if gap > self.max_correlation_window_seconds:
            return False, f"Gap ({int(gap)}s) exceeds max correlation window ({self.max_correlation_window_seconds}s)"

        if sequence_start_time:
            seq_utc = sequence_start_time if sequence_start_time.tzinfo else sequence_start_time.replace(tzinfo=timezone.utc)
            total_span = abs((max(a_utc, b_utc) - seq_utc).total_seconds())
            if total_span > self.max_sequence_span_seconds:
                return False, f"Total span ({int(total_span)}s) exceeds max sequence span ({self.max_sequence_span_seconds}s)"

        return True, "Within allowable temporal correlation window"

    def match_behavioral_pattern(
        self,
        sessions: List[Dict[str, Any]],
        detections: List[Dict[str, Any]],
        mappings: List[Dict[str, Any]],
    ) -> Optional[Tuple[SequencePatternType, str, str]]:
        """Evaluates sessions and detections against recognized multi-session behavioral patterns.
        
        Returns:
            (PatternType, SequenceTitle, DiagnosticRationale) or None
        """
        if len(sessions) < self.min_sessions:
            return None

        # Sort sessions chronologically
        sorted_sessions = sorted(sessions, key=lambda s: s["first_observed_at"])
        rule_ids = {d.get("detection_rule_id") for d in detections if d.get("detection_rule_id")}
        tech_ids = {m.get("technique_id") for m in mappings if m.get("technique_id")}
        event_cats = set()
        for s in sessions:
            meta = s.get("metadata_summary") or {}
            if meta.get("initial_category"):
                event_cats.add(meta.get("initial_category"))

        # Check decoy consistency / cross-protocol
        honeypot_types = {s.get("honeypot_type") for s in sessions if s.get("honeypot_type")}
        decoy_ids = {s.get("decoy_id") for s in sessions if s.get("decoy_id")}

        # ---------------------------------------------------------------------
        # Pattern 4: Multi-Technique Progression (ATT&CK aligned)
        # ---------------------------------------------------------------------
        # E.g. T1110 (Credential Access) -> T1083 / T1087 (Discovery) -> T1190 (Exploitation)
        has_cred_access = bool(tech_ids.intersection({"T1110", "T1110.001", "T1078"}))
        has_discovery = bool(tech_ids.intersection({"T1083", "T1087", "T1087.001"}))
        has_exploit = bool(tech_ids.intersection({"T1190"}))

        if (has_cred_access and (has_discovery or has_exploit)) or (has_discovery and has_exploit):
            return (
                SequencePatternType.MULTI_TECHNIQUE_PROGRESSION,
                "Multi-Stage ATT&CK Technique Progression",
                f"Observed sequential progression across ATT&CK techniques: {sorted(list(tech_ids))}",
            )

        # ---------------------------------------------------------------------
        # Pattern 3: Enumeration Followed by Suspicious Requests / Exploit
        # ---------------------------------------------------------------------
        has_enum_rule = bool(rule_ids.intersection({"AUTH-003", "WEB-001"}))
        has_exploit_rule = bool(rule_ids.intersection({"WEB-002", "CMD-001", "FILE-001"}))
        if has_enum_rule and has_exploit_rule:
            return (
                SequencePatternType.ENUMERATION_THEN_EXPLOIT,
                "Directory/Account Enumeration Preceding Exploit Probes",
                "Observed discovery probing in early session followed by targeted exploit attempts in subsequent session",
            )

        # ---------------------------------------------------------------------
        # Pattern 2: Authentication Probing Followed by Enumeration
        # ---------------------------------------------------------------------
        has_auth_rule = bool(rule_ids.intersection({"AUTH-001", "AUTH-002"}))
        if has_auth_rule and has_enum_rule:
            return (
                SequencePatternType.AUTH_THEN_ENUMERATION,
                "Authentication Attempts Preceding Resource Enumeration",
                "Observed authentication attempts followed by systematic path or username discovery across sessions",
            )

        # ---------------------------------------------------------------------
        # Pattern 6: Validated Cross-Protocol Observations
        # ---------------------------------------------------------------------
        if len(honeypot_types) > 1 and len(detections) >= 2:
            return (
                SequencePatternType.CROSS_PROTOCOL_INTERACTION,
                "Coordinated Multi-Protocol Decoy Probing",
                f"Observed related suspicious interactions across multiple protocols ({sorted(list(honeypot_types))}) within correlation window",
            )

        # ---------------------------------------------------------------------
        # Pattern 1: Repeated Authentication Activity
        # ---------------------------------------------------------------------
        if has_auth_rule or "authentication" in event_cats or "auth" in event_cats:
            return (
                SequencePatternType.REPEATED_AUTHENTICATION,
                "Recurring Multi-Session Authentication Activity",
                f"Observed repeated authentication attempts across {len(sessions)} distinct activity sessions",
            )

        # ---------------------------------------------------------------------
        # Pattern 5: Repeated Honeypot Target Interactions
        # ---------------------------------------------------------------------
        if len(decoy_ids) == 1 and len(sessions) >= 2 and len(detections) >= 1:
            decoy_name = list(decoy_ids)[0]
            return (
                SequencePatternType.RECURRING_HONEYPOT_TARGET,
                f"Recurring Interaction Sequence Against {decoy_name}",
                f"Observed {len(sessions)} distinct suspicious interaction sessions targeting decoy {decoy_name}",
            )

        # Insufficient behavioral pattern match
        return None


# Default global policy instance
default_sequence_policy = CrossSessionCorrelationPolicy()

