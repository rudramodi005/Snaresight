"""Official Scenario Catalogue for SnareSight Threat Detection Engine.

Defines the 10 concrete, explainable detection scenarios for authentication,
enumeration, traversal, command discovery, file transfer, and behavioral anomalies.
"""

from typing import Dict, List
from app.detection.rule_schema import (
    AtomicCondition,
    ConditionGroup,
    DetectionRuleDefinition,
    DetectionType,
    EvaluationMode,
    RuleSeverity,
    RuleStatus,
    ThresholdConfiguration,
)
from app.detection.registry import RuleRegistry, rule_registry


def get_all_scenarios() -> List[DetectionRuleDefinition]:
    """Returns the full catalogue of 10 standard SnareSight detection rules."""
    return [
        # SCENARIO 01: Repeated Authentication Failures
        DetectionRuleDefinition(
            rule_id="AUTH-001",
            rule_name="Repeated Authentication Failures",
            rule_version="1.0",
            description=(
                "Identifies repeated authentication failure attempts within a validated session or "
                "time window on the web-login honeypot. Evidence of credential guessing or automated probing."
            ),
            category="AUTHENTICATION",
            subcategory="CREDENTIAL_PROBING",
            detection_type=DetectionType.THRESHOLD,
            evaluation_mode=EvaluationMode.SESSION,
            enabled=True,
            rule_status=RuleStatus.ACTIVE,
            conditions=ConditionGroup(
                all=[
                    AtomicCondition(field="event_category", operator="EQUALS", value="authentication"),
                    AtomicCondition(field="outcome", operator="EQUALS", value="FAILURE"),
                ]
            ),
            threshold_configuration=ThresholdConfiguration(threshold=3, group_by=["session_id"]),
            time_window_seconds=300,
            severity_default=RuleSeverity.MEDIUM,
            rule_source="builtin_catalogue",
        ),

        # SCENARIO 02: Decoy Authentication Acceptance
        DetectionRuleDefinition(
            rule_id="AUTH-002",
            rule_name="Decoy Authentication Interaction Accepted",
            rule_version="1.0",
            description=(
                "Identifies simulated successful authentication on the decoy (trap account accepted). "
                "Simulated decoy acceptance is NOT real access to a production system."
            ),
            category="AUTHENTICATION",
            subcategory="DECOY_COMPROMISE_SIMULATION",
            detection_type=DetectionType.SINGLE_EVENT,
            evaluation_mode=EvaluationMode.EVENT,
            enabled=True,
            rule_status=RuleStatus.ACTIVE,
            conditions=ConditionGroup(
                all=[
                    AtomicCondition(field="event_category", operator="EQUALS", value="authentication"),
                    AtomicCondition(field="outcome", operator="EQUALS", value="SUCCESS"),
                ]
            ),
            severity_default=RuleSeverity.HIGH,
            rule_source="builtin_catalogue",
        ),

        # SCENARIO 03: Username Enumeration
        DetectionRuleDefinition(
            rule_id="AUTH-003",
            rule_name="Username Enumeration Probing",
            rule_version="1.0",
            description=(
                "Identifies patterns consistent with attempts to discover or test valid usernames "
                "by counting distinct privacy-safe username fingerprints within a session."
            ),
            category="RECONNAISSANCE",
            subcategory="ACCOUNT_DISCOVERY",
            detection_type=DetectionType.THRESHOLD,
            evaluation_mode=EvaluationMode.SESSION,
            enabled=True,
            rule_status=RuleStatus.ACTIVE,
            conditions=ConditionGroup(
                all=[
                    AtomicCondition(field="event_category", operator="EQUALS", value="authentication"),
                    AtomicCondition(field="metadata.username_fingerprint", operator="EXISTS", value=None),
                ]
            ),
            threshold_configuration=ThresholdConfiguration(threshold=3, group_by=["session_id"]),
            time_window_seconds=300,
            severity_default=RuleSeverity.MEDIUM,
            rule_source="builtin_catalogue",
        ),

        # SCENARIO 04: Web Path Enumeration
        DetectionRuleDefinition(
            rule_id="WEB-001",
            rule_name="Web Path Enumeration Probing",
            rule_version="1.0",
            description=(
                "Identifies repeated scanning and enumeration of distinct web paths on the decoy "
                "within a session or sliding time window."
            ),
            category="RECONNAISSANCE",
            subcategory="ENDPOINT_DISCOVERY",
            detection_type=DetectionType.THRESHOLD,
            evaluation_mode=EvaluationMode.SESSION,
            enabled=True,
            rule_status=RuleStatus.ACTIVE,
            conditions=ConditionGroup(
                all=[
                    AtomicCondition(field="event_category", operator="EQUALS", value="request"),
                    AtomicCondition(field="metadata.http_path", operator="EXISTS", value=None),
                ]
            ),
            threshold_configuration=ThresholdConfiguration(threshold=3, group_by=["session_id"]),
            time_window_seconds=300,
            severity_default=RuleSeverity.LOW,
            rule_source="builtin_catalogue",
        ),

        # SCENARIO 05: Suspicious Directory Traversal Requests
        DetectionRuleDefinition(
            rule_id="WEB-002",
            rule_name="Suspicious Directory Traversal Request",
            rule_version="1.0",
            description=(
                "Identifies HTTP requests containing known safe traversal indicators (../, ..%2f, %2e%2e/). "
                "Passive pattern matching only; requested paths are never executed or resolved on filesystem."
            ),
            category="EXPLOITATION",
            subcategory="DIRECTORY_TRAVERSAL",
            detection_type=DetectionType.SINGLE_EVENT,
            evaluation_mode=EvaluationMode.EVENT,
            enabled=True,
            rule_status=RuleStatus.ACTIVE,
            conditions=ConditionGroup(
                any=[
                    AtomicCondition(field="metadata.http_path", operator="CONTAINS", value="../"),
                    AtomicCondition(field="metadata.http_path", operator="CONTAINS", value="..%2f"),
                    AtomicCondition(field="metadata.http_path", operator="CONTAINS", value="..%2F"),
                    AtomicCondition(field="metadata.http_path", operator="CONTAINS", value="%2e%2e%2f"),
                    AtomicCondition(field="metadata.http_path", operator="CONTAINS", value="%2e%2e/"),
                    AtomicCondition(field="metadata.http_path", operator="CONTAINS", value="..\\"),
                    AtomicCondition(field="metadata.http_path", operator="CONTAINS", value="..%5c"),
                ]
            ),
            severity_default=RuleSeverity.HIGH,
            rule_source="builtin_catalogue",
        ),

        # SCENARIO 06: Command Discovery Interactions (Marked DEFERRED)
        DetectionRuleDefinition(
            rule_id="CMD-001",
            rule_name="Command Discovery Interaction (Deferred)",
            rule_version="1.0",
            description=(
                "Identifies environment discovery commands in interactive honeypots (DEFERRED: WEB-001 decoy "
                "does not provide shell access; text only, commands are never executed)."
            ),
            category="COMMAND_EXECUTION",
            subcategory="ENVIRONMENT_DISCOVERY",
            detection_type=DetectionType.SINGLE_EVENT,
            evaluation_mode=EvaluationMode.EVENT,
            enabled=False,  # Explicitly deferred until shell/Cowrie integration
            rule_status=RuleStatus.DRAFT,
            conditions=ConditionGroup(
                all=[
                    AtomicCondition(
                        field="metadata.command_category",
                        operator="IN",
                        value=["sys_info", "identity", "dir_listing", "network_recon"],
                    ),
                ]
            ),
            severity_default=RuleSeverity.MEDIUM,
            rule_source="builtin_catalogue",
        ),

        # SCENARIO 07: File-Transfer Attempts (Marked DEFERRED)
        DetectionRuleDefinition(
            rule_id="FILE-001",
            rule_name="File Transfer Interaction (Deferred)",
            rule_version="1.0",
            description=(
                "Identifies file transfer attempts in honeypot telemetry (DEFERRED: WEB-001 decoy "
                "does not support file transfers; files never executed or opened)."
            ),
            category="APPLICATION",
            subcategory="FILE_TRANSFER",
            detection_type=DetectionType.SINGLE_EVENT,
            evaluation_mode=EvaluationMode.EVENT,
            enabled=False,  # Explicitly deferred until file-transfer honeypot adapter approved
            rule_status=RuleStatus.DRAFT,
            conditions=ConditionGroup(
                all=[
                    AtomicCondition(
                        field="metadata.transfer_direction",
                        operator="IN",
                        value=["UPLOAD", "DOWNLOAD"],
                    ),
                ]
            ),
            severity_default=RuleSeverity.MEDIUM,
            rule_source="builtin_catalogue",
        ),

        # SCENARIO 08: Repeated Suspicious Request Patterns
        DetectionRuleDefinition(
            rule_id="WEB-003",
            rule_name="Repeated Suspicious Request Patterns",
            rule_version="1.0",
            description=(
                "Identifies repeated suspicious HTTP request patterns within a validated session, "
                "such as repeated probe markers or classification anomalies."
            ),
            category="APPLICATION",
            subcategory="ANOMALOUS_PROBING",
            detection_type=DetectionType.THRESHOLD,
            evaluation_mode=EvaluationMode.SESSION,
            enabled=True,
            rule_status=RuleStatus.ACTIVE,
            conditions=ConditionGroup(
                all=[
                    AtomicCondition(field="metadata.request_pattern", operator="EXISTS", value=None),
                ]
            ),
            threshold_configuration=ThresholdConfiguration(threshold=3, group_by=["session_id"]),
            time_window_seconds=300,
            severity_default=RuleSeverity.MEDIUM,
            rule_source="builtin_catalogue",
        ),

        # SCENARIO 09: Multi-Category Suspicious Interaction
        DetectionRuleDefinition(
            rule_id="BEHAV-001",
            rule_name="Multi-Category Suspicious Interaction",
            rule_version="1.0",
            description=(
                "Identifies sessions exhibiting multiple distinct categories of suspicious activity "
                "(e.g., authentication probing combined with web request enumeration)."
            ),
            category="APPLICATION",
            subcategory="MULTI_VECTOR_BEHAVIOR",
            detection_type=DetectionType.CORRELATION,
            evaluation_mode=EvaluationMode.SESSION,
            enabled=True,
            rule_status=RuleStatus.ACTIVE,
            conditions=ConditionGroup(
                any=[
                    AtomicCondition(field="event_category", operator="EQUALS", value="authentication"),
                    AtomicCondition(field="event_category", operator="EQUALS", value="request"),
                ]
            ),
            threshold_configuration=ThresholdConfiguration(threshold=2, group_by=["session_id"]),
            time_window_seconds=600,
            severity_default=RuleSeverity.HIGH,
            rule_source="builtin_catalogue",
        ),

        # SCENARIO 10: Unusual or Abnormal Request Behavior
        DetectionRuleDefinition(
            rule_id="BEHAV-002",
            rule_name="Unusual HTTP Method Interaction",
            rule_version="1.0",
            description=(
                "Identifies HTTP requests using unexpected methods (e.g. TRACE, TRACK, PROPFIND, DEBUG) "
                "indicative of scanner probing or capability profiling."
            ),
            category="APPLICATION",
            subcategory="UNUSUAL_METHOD",
            detection_type=DetectionType.SINGLE_EVENT,
            evaluation_mode=EvaluationMode.EVENT,
            enabled=True,
            rule_status=RuleStatus.ACTIVE,
            conditions=ConditionGroup(
                all=[
                    AtomicCondition(
                        field="metadata.http_method",
                        operator="IN",
                        value=["TRACE", "TRACK", "PROPFIND", "PUT", "DELETE", "DEBUG"],
                    ),
                ]
            ),
            severity_default=RuleSeverity.MEDIUM,
            rule_source="builtin_catalogue",
        ),
    ]


def register_scenario_catalogue(registry: RuleRegistry = rule_registry) -> None:
    """Registers all 10 catalogue rules into the provided RuleRegistry."""
    for rule in get_all_scenarios():
        # Register or update
        if registry.is_rule_registered(rule.rule_id, rule.rule_version):
            continue
        registry.register_rule(rule)

