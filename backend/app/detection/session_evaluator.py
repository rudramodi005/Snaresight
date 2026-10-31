"""Session-level evaluation foundations for SnareSight detection engine.

Provides bounded querying, chronological ordering, path normalization, deduplication,
and aggregation interfaces for evaluating sequences of related events within a validated session.
"""

import urllib.parse
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import asc
from app.db.models.event import SecurityEventModel
from app.detection.rule_schema import DetectionRuleDefinition


class SessionEvaluator:
    """Evaluates multi-event session contexts against session-scoped rules."""

    MAX_SESSION_EVENTS = 100

    @classmethod
    def get_session_events(
        cls,
        db: Session,
        session_id: str,
        limit: int = MAX_SESSION_EVENTS,
    ) -> List[SecurityEventModel]:
        """Retrieves events for a session ordered chronologically by observed time.
        
        Enforces explicit session boundaries without merging unrelated sessions.
        """
        if not session_id or not session_id.strip():
            return []

        bounded_limit = min(limit, cls.MAX_SESSION_EVENTS)
        return (
            db.query(SecurityEventModel)
            .filter(SecurityEventModel.session_id == session_id)
            .order_by(asc(SecurityEventModel.observed_at))
            .limit(bounded_limit)
            .all()
        )

    @classmethod
    def normalize_path(cls, path: Optional[str]) -> str:
        """Safely normalizes an HTTP URL path string.
        
        INVARIANT: Pure string normalization. Never accesses or resolves against
        the host filesystem.
        """
        if not path or not isinstance(path, str):
            return "/"
        
        # URL decode to resolve %2e%2e, %2f, etc.
        try:
            unquoted = urllib.parse.unquote(path)
        except Exception:
            unquoted = path

        # Strip redundant trailing slashes unless root
        normalized = unquoted.strip()
        if len(normalized) > 1 and normalized.endswith("/"):
            normalized = normalized.rstrip("/")
            
        return normalized

    @classmethod
    def filter_events_by_window(
        cls,
        events: List[Any],
        reference_time: datetime,
        window_seconds: int,
    ) -> List[Any]:
        """Filters events to only those falling within [reference_time - window_seconds, reference_time]."""
        ref_utc = reference_time if reference_time.tzinfo else reference_time.replace(tzinfo=timezone.utc)
        start_time = ref_utc - timedelta(seconds=max(1, window_seconds))

        filtered: List[Any] = []
        for ev in events:
            obs_dt = cls._get_observed_at(ev)
            if obs_dt is not None:
                obs_utc = obs_dt if obs_dt.tzinfo else obs_dt.replace(tzinfo=timezone.utc)
                if start_time <= obs_utc <= ref_utc:
                    filtered.append(ev)
        return filtered

    @classmethod
    def count_distinct_username_fingerprints(
        cls,
        events: List[Any],
    ) -> Tuple[int, Set[str]]:
        """Counts distinct privacy-safe username fingerprints across session events.
        
        INVARIANT: Operates on one-way fingerprints only; plaintext usernames are
        neither required nor stored.
        """
        seen_events: Set[str] = set()
        fingerprints: Set[str] = set()

        for ev in events:
            eid = cls._get_event_id(ev)
            if eid and eid in seen_events:
                continue
            if eid:
                seen_events.add(eid)

            fp = cls._extract_meta_field(ev, "username_fingerprint")
            if fp and isinstance(fp, str) and fp.strip():
                fingerprints.add(fp.strip())

        return len(fingerprints), fingerprints

    @classmethod
    def count_distinct_paths(
        cls,
        events: List[Any],
    ) -> Tuple[int, Set[str]]:
        """Counts distinct normalized HTTP paths probed across session events."""
        seen_events: Set[str] = set()
        paths: Set[str] = set()

        for ev in events:
            eid = cls._get_event_id(ev)
            if eid and eid in seen_events:
                continue
            if eid:
                seen_events.add(eid)

            raw_path = cls._extract_meta_field(ev, "http_path") or cls._extract_meta_field(ev, "path")
            if raw_path and isinstance(raw_path, str) and raw_path.strip():
                norm_p = cls.normalize_path(raw_path)
                paths.add(norm_p)

        return len(paths), paths

    @classmethod
    def count_distinct_categories(
        cls,
        events: List[Any],
    ) -> Tuple[int, Set[str]]:
        """Counts distinct security event categories observed within the session."""
        seen_events: Set[str] = set()
        categories: Set[str] = set()

        for ev in events:
            eid = cls._get_event_id(ev)
            if eid and eid in seen_events:
                continue
            if eid:
                seen_events.add(eid)

            cat = cls._get_field(ev, "event_category")
            if cat and isinstance(cat, str) and cat.strip():
                categories.add(cat.strip().lower())

        return len(categories), categories

    @classmethod
    def count_suspicious_patterns(
        cls,
        events: List[Any],
    ) -> Tuple[int, List[str]]:
        """Counts occurrences of suspicious request patterns or indicators within the session."""
        seen_events: Set[str] = set()
        matched_eids: List[str] = []

        for ev in events:
            eid = cls._get_event_id(ev)
            if eid and eid in seen_events:
                continue
            if eid:
                seen_events.add(eid)

            pat = cls._extract_meta_field(ev, "request_pattern")
            raw_path = cls._extract_meta_field(ev, "http_path") or ""
            is_suspicious = False

            if pat and isinstance(pat, str) and pat.strip():
                is_suspicious = True
            elif "../" in raw_path or "..%2f" in raw_path.lower() or "%2e%2e" in raw_path.lower():
                is_suspicious = True

            if is_suspicious and eid:
                matched_eids.append(eid)

        return len(matched_eids), matched_eids

    @classmethod
    def count_matching_condition_events(
        cls,
        events: List[Any],
        event_category: Optional[str] = None,
        outcome: Optional[str] = None,
    ) -> Tuple[int, List[str]]:
        """Counts unique events matching specific category and outcome within the session."""
        seen_events: Set[str] = set()
        matching_ids: List[str] = []

        for ev in events:
            eid = cls._get_event_id(ev)
            if eid and eid in seen_events:
                continue
            if eid:
                seen_events.add(eid)

            if event_category:
                cat = cls._get_field(ev, "event_category")
                if not cat or str(cat).strip().lower() != str(event_category).strip().lower():
                    continue
            if outcome:
                out = cls._get_field(ev, "outcome")
                if not out or str(out).strip().lower() != str(outcome).strip().lower():
                    continue

            if eid:
                matching_ids.append(eid)

        return len(matching_ids), matching_ids

    # --- Internal extraction helpers ---

    @classmethod
    def _get_event_id(cls, ev: Any) -> Optional[str]:
        if isinstance(ev, dict):
            return str(ev.get("event_id", ""))
        return str(getattr(ev, "event_id", ""))

    @classmethod
    def _get_field(cls, ev: Any, field_name: str) -> Any:
        if isinstance(ev, dict):
            return ev.get(field_name)
        return getattr(ev, field_name, None)

    @classmethod
    def _extract_meta_field(cls, ev: Any, subfield: str) -> Any:
        meta = cls._get_field(ev, "sanitized_metadata") or cls._get_field(ev, "service_metadata") or {}
        if isinstance(meta, dict):
            if subfield in meta:
                return meta.get(subfield)
            for sec in ("auth", "http", "command", "file"):
                nested = meta.get(sec)
                if isinstance(nested, dict):
                    if subfield in nested:
                        return nested.get(subfield)
                    if subfield == "http_path" and "path" in nested:
                        return nested.get("path")
                    if subfield == "http_method" and "method" in nested:
                        return nested.get("method")
        return None

    @classmethod
    def _get_observed_at(cls, ev: Any) -> Optional[datetime]:
        obs = cls._get_field(ev, "observed_at")
        if isinstance(obs, datetime):
            return obs
        if isinstance(obs, str):
            try:
                return datetime.fromisoformat(obs.replace("Z", "+00:00"))
            except Exception:
                return None
        return None
