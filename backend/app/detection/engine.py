"""Core rule-based threat detection engine for SnareSight.

Coordinates rule selection, condition evaluation, session/window aggregation,
result generation, execution auditing, and idempotency guarantees for normalized honeypot events.
"""

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session
from app.db.models.event import SecurityEventModel
from app.detection.event_matcher import EventMatcher
from app.detection.exceptions import DetectionError, RuleValidationError, UnsupportedFieldError
from app.detection.execution_tracker import ExecutionTracker, execution_tracker
from app.detection.registry import RuleRegistry, rule_registry
from app.detection.result_builder import ResultBuilder
from app.detection.rule_schema import DetectionRuleDefinition, EvaluationMode
from app.detection.session_evaluator import SessionEvaluator
from app.schemas.detection import DetectionResult, EvaluationStatus


class DetectionEngine:
    """Evaluates normalized events against registered detection rules."""

    def __init__(
        self,
        registry: Optional[RuleRegistry] = None,
        tracker: Optional[ExecutionTracker] = None,
    ):
        self.registry = registry or rule_registry
        self.tracker = tracker or execution_tracker

    def evaluate_event(
        self,
        event: Dict[str, Any] | SecurityEventModel,
        rules: Optional[List[DetectionRuleDefinition]] = None,
        db: Optional[Session] = None,
        session_events: Optional[List[Any]] = None,
    ) -> List[DetectionResult]:
        """Evaluates a single normalized event against applicable enabled detection rules.
        
        Guarantees:
        - Safe execution without dynamic code generation.
        - Isolation: failure in one rule does not terminate evaluation of peer rules.
        - Idempotency: duplicate submissions of the same event and rule version return cached results.
        - Context awareness: supports session-scoped and temporal-window multi-event evaluation.
        """
        event_dict = self._normalize_event_input(event)
        event_id = str(event_dict.get("event_id", ""))

        if not event_id:
            return []

        # Target rules: either passed explicitly or all enabled rules
        target_rules = rules if rules is not None else self.registry.list_enabled_rules()

        results: List[DetectionResult] = []

        for rule in target_rules:
            # 1. Idempotency Check
            if self.tracker.has_been_evaluated(event_id, rule.rule_id, rule.rule_version):
                cached = self.tracker.get_cached_result(event_id, rule.rule_id, rule.rule_version)
                if cached:
                    results.append(cached)
                continue

            # 2. Check operational enabled status
            if not rule.enabled:
                res = ResultBuilder.build_result(
                    rule=rule,
                    event=event_dict,
                    status=EvaluationStatus.SKIPPED,
                    explanation=f"Rule '{rule.rule_id}' is disabled or deferred. Evaluation skipped.",
                )
                self.tracker.record_result(res)
                self.tracker.record_execution(
                    rule_id=rule.rule_id,
                    rule_version=rule.rule_version,
                    event_id=event_id,
                    status=EvaluationStatus.SKIPPED,
                    duration_ms=0.0,
                    result_id=res.detection_result_id,
                )
                results.append(res)
                continue

            # 3. Timed Evaluation
            start_time = time.perf_counter()
            try:
                if rule.evaluation_mode == EvaluationMode.EVENT:
                    matched, matched_conds, explanation = EventMatcher.evaluate_rule(event_dict, rule)
                    related_eids: List[str] = []
                else:
                    matched, matched_conds, explanation, related_eids = self._evaluate_multi_event_rule(
                        event_dict=event_dict,
                        rule=rule,
                        db=db,
                        session_events=session_events,
                    )

                status = EvaluationStatus.MATCHED if matched else EvaluationStatus.NO_MATCH

                res = ResultBuilder.build_result(
                    rule=rule,
                    event=event_dict,
                    status=status,
                    explanation=explanation,
                    matched_conditions=matched_conds,
                    related_event_ids=related_eids,
                )
                duration_ms = (time.perf_counter() - start_time) * 1000.0

                self.tracker.record_result(res)
                self.tracker.record_execution(
                    rule_id=rule.rule_id,
                    rule_version=rule.rule_version,
                    event_id=event_id,
                    status=status,
                    duration_ms=duration_ms,
                    result_id=res.detection_result_id,
                )
                results.append(res)

            except (RuleValidationError, UnsupportedFieldError) as err:
                duration_ms = (time.perf_counter() - start_time) * 1000.0
                res = ResultBuilder.build_result(
                    rule=rule,
                    event=event_dict,
                    status=EvaluationStatus.INVALID_RULE,
                    explanation=f"Rule evaluation aborted due to schema/field error: {str(err)}",
                )
                self.tracker.record_result(res)
                self.tracker.record_execution(
                    rule_id=rule.rule_id,
                    rule_version=rule.rule_version,
                    event_id=event_id,
                    status=EvaluationStatus.INVALID_RULE,
                    duration_ms=duration_ms,
                    result_id=res.detection_result_id,
                    error_category="validation_error",
                )
                results.append(res)

            except Exception as exc:
                duration_ms = (time.perf_counter() - start_time) * 1000.0
                res = ResultBuilder.build_result(
                    rule=rule,
                    event=event_dict,
                    status=EvaluationStatus.EVALUATION_ERROR,
                    explanation=f"Unexpected evaluator error: {str(exc)}",
                )
                self.tracker.record_result(res)
                self.tracker.record_execution(
                    rule_id=rule.rule_id,
                    rule_version=rule.rule_version,
                    event_id=event_id,
                    status=EvaluationStatus.EVALUATION_ERROR,
                    duration_ms=duration_ms,
                    result_id=res.detection_result_id,
                    error_category="runtime_error",
                )
                results.append(res)

        return results

    def _evaluate_multi_event_rule(
        self,
        event_dict: Dict[str, Any],
        rule: DetectionRuleDefinition,
        db: Optional[Session] = None,
        session_events: Optional[List[Any]] = None,
    ) -> Tuple[bool, List[Dict[str, Any]], str, List[str]]:
        """Evaluates multi-event session and time-window rules with explicit boundaries."""
        base_matched, matched_conds, base_expl = EventMatcher.evaluate_rule(event_dict, rule)
        if not base_matched:
            return False, matched_conds, f"Event {event_dict.get('event_id')} does not match base conditions for rule '{rule.rule_id}'.", []

        session_id = str(event_dict.get("session_id", ""))
        current_eid = str(event_dict.get("event_id", ""))

        # Gather session events
        if session_events is not None:
            events = list(session_events)
        elif db is not None and session_id:
            events = SessionEvaluator.get_session_events(db, session_id)
        else:
            events = [event_dict]

        # Ensure the evaluated event is present in the list
        has_current = False
        for ev in events:
            if SessionEvaluator._get_event_id(ev) == current_eid:
                has_current = True
                break
        if not has_current:
            events.append(event_dict)

        # Apply time window filtering if configured
        if rule.time_window_seconds:
            ref_dt = SessionEvaluator._get_observed_at(event_dict) or datetime.now(timezone.utc)
            events = SessionEvaluator.filter_events_by_window(events, ref_dt, rule.time_window_seconds)

        threshold = rule.threshold_configuration.threshold if rule.threshold_configuration else 3

        # Scenario-specific evaluation logic
        if rule.rule_id == "AUTH-001":
            count, matching_eids = SessionEvaluator.count_matching_condition_events(
                events, event_category="authentication", outcome="FAILURE"
            )
            matched = count >= threshold
            if matched:
                expl = (
                    f"Rule '{rule.rule_id}' (v{rule.rule_version}: {rule.rule_name}) MATCHED: "
                    f"Observed {count} authentication failure attempts in session '{session_id}' "
                    f"(threshold: {threshold})."
                )
                rel_ids = [eid for eid in matching_eids if eid != current_eid]
            else:
                expl = (
                    f"Rule '{rule.rule_id}' (v{rule.rule_version}) NO_MATCH: "
                    f"Observed {count} authentication failures (threshold: {threshold})."
                )
                rel_ids = []
            return matched, matched_conds, expl, rel_ids

        elif rule.rule_id == "AUTH-003":
            count, fps = SessionEvaluator.count_distinct_username_fingerprints(events)
            matched = count >= threshold
            if matched:
                expl = (
                    f"Rule '{rule.rule_id}' (v{rule.rule_version}: {rule.rule_name}) MATCHED: "
                    f"Observed {count} distinct username fingerprints in session '{session_id}' "
                    f"(threshold: {threshold})."
                )
                rel_ids = [SessionEvaluator._get_event_id(e) for e in events if SessionEvaluator._get_event_id(e) != current_eid]
            else:
                expl = (
                    f"Rule '{rule.rule_id}' (v{rule.rule_version}) NO_MATCH: "
                    f"Observed {count} distinct username fingerprints (threshold: {threshold})."
                )
                rel_ids = []
            return matched, matched_conds, expl, rel_ids

        elif rule.rule_id == "WEB-001":
            count, paths = SessionEvaluator.count_distinct_paths(events)
            matched = count >= threshold
            if matched:
                expl = (
                    f"Rule '{rule.rule_id}' (v{rule.rule_version}: {rule.rule_name}) MATCHED: "
                    f"Observed {count} distinct HTTP paths probed in session '{session_id}' "
                    f"(threshold: {threshold})."
                )
                rel_ids = [SessionEvaluator._get_event_id(e) for e in events if SessionEvaluator._get_event_id(e) != current_eid]
            else:
                expl = (
                    f"Rule '{rule.rule_id}' (v{rule.rule_version}) NO_MATCH: "
                    f"Observed {count} distinct HTTP paths probed (threshold: {threshold})."
                )
                rel_ids = []
            return matched, matched_conds, expl, rel_ids

        elif rule.rule_id == "WEB-003":
            count, pat_eids = SessionEvaluator.count_suspicious_patterns(events)
            matched = count >= threshold
            if matched:
                expl = (
                    f"Rule '{rule.rule_id}' (v{rule.rule_version}: {rule.rule_name}) MATCHED: "
                    f"Observed {count} repeated suspicious request patterns in session '{session_id}' "
                    f"(threshold: {threshold})."
                )
                rel_ids = [eid for eid in pat_eids if eid != current_eid]
            else:
                expl = (
                    f"Rule '{rule.rule_id}' (v{rule.rule_version}) NO_MATCH: "
                    f"Observed {count} suspicious request patterns (threshold: {threshold})."
                )
                rel_ids = []
            return matched, matched_conds, expl, rel_ids

        elif rule.rule_id == "BEHAV-001":
            count, cats = SessionEvaluator.count_distinct_categories(events)
            matched = count >= threshold
            if matched:
                expl = (
                    f"Rule '{rule.rule_id}' (v{rule.rule_version}: {rule.rule_name}) MATCHED: "
                    f"Observed {count} distinct security categories ({sorted(list(cats))}) in session '{session_id}' "
                    f"(threshold: {threshold})."
                )
                rel_ids = [SessionEvaluator._get_event_id(e) for e in events if SessionEvaluator._get_event_id(e) != current_eid]
            else:
                expl = (
                    f"Rule '{rule.rule_id}' (v{rule.rule_version}) NO_MATCH: "
                    f"Observed {count} security categories (threshold: {threshold})."
                )
                rel_ids = []
            return matched, matched_conds, expl, rel_ids

        # Generic fallback threshold counting
        matching_count = 0
        matching_eids = []
        for ev in events:
            ev_dict = self._normalize_event_input(ev)
            m, _, _ = EventMatcher.evaluate_rule(ev_dict, rule)
            if m:
                matching_count += 1
                eid = ev_dict.get("event_id")
                if eid:
                    matching_eids.append(eid)

        matched = matching_count >= threshold
        if matched:
            expl = f"Rule '{rule.rule_id}' MATCHED: {matching_count} events met condition (threshold: {threshold})."
            rel_ids = [eid for eid in matching_eids if eid != current_eid]
        else:
            expl = f"Rule '{rule.rule_id}' NO_MATCH: {matching_count} events met condition (threshold: {threshold})."
            rel_ids = []

        return matched, matched_conds, expl, rel_ids

    def _normalize_event_input(self, event: Dict[str, Any] | SecurityEventModel) -> Dict[str, Any]:
        """Converts SecurityEventModel or dictionary into a standardized evaluation dictionary."""
        if isinstance(event, SecurityEventModel):
            return {
                "event_id": str(event.event_id),
                "raw_event_id": str(event.raw_event_id),
                "event_type": event.event_type,
                "event_category": event.event_category,
                "action": event.action,
                "outcome": event.outcome,
                "decoy_id": event.decoy_id,
                "session_id": event.session_id,
                "source_address": event.source_address,
                "source_port": event.source_port,
                "source_protocol": event.source_protocol,
                "target_service": event.target_service,
                "target_port": event.target_port,
                "observed_at": event.observed_at.isoformat() if event.observed_at else None,
                "received_at": event.received_at.isoformat() if event.received_at else None,
                "sanitized_metadata": event.sanitized_metadata or {},
                "provenance": event.provenance or {},
            }
        return dict(event)


# Default module-level singleton engine
detection_engine = DetectionEngine()

try:
    from app.detection.scenario_catalogue import register_scenario_catalogue
    register_scenario_catalogue(rule_registry)
except Exception:
    pass
