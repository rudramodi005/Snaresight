"""Demonstration Scenario Definitions and Metadata Catalog for SnareSight."""

from typing import Dict, List
from app.modules.demo.schemas import DatasetSize, ScenarioMeta, ScenarioType

SCENARIO_CATALOG: Dict[ScenarioType, ScenarioMeta] = {
    ScenarioType.SCENARIO_A: ScenarioMeta(
        scenario_id=ScenarioType.SCENARIO_A,
        title="Scenario A: Repeated Login Failures",
        description=(
            "Simulates rapid credential guessing against a web login honeypot decoy. "
            "Triggers AUTH-001 (threshold: 3 failures in session) and maps to MITRE T1110 (Brute Force)."
        ),
        mitre_techniques=["T1110", "T1110.001"],
        expected_rules=["AUTH-001"],
        target_decoy="WEB-001",
        estimated_events={"SMALL": 25, "MEDIUM": 100, "LARGE": 500},
    ),
    ScenarioType.SCENARIO_B: ScenarioMeta(
        scenario_id=ScenarioType.SCENARIO_B,
        title="Scenario B: Username Enumeration Probing",
        description=(
            "Simulates systematic account discovery probing across multiple common usernames (admin, root, deploy). "
            "Triggers AUTH-003 and maps to MITRE T1087 (Account Discovery)."
        ),
        mitre_techniques=["T1087", "T1087.002"],
        expected_rules=["AUTH-003"],
        target_decoy="WEB-001",
        estimated_events={"SMALL": 25, "MEDIUM": 100, "LARGE": 500},
    ),
    ScenarioType.SCENARIO_C: ScenarioMeta(
        scenario_id=ScenarioType.SCENARIO_C,
        title="Scenario C: Suspicious Web Path Requests & Traversal",
        description=(
            "Simulates web application directory traversal and endpoint reconnaissance against decoys. "
            "Triggers WEB-001 and WEB-002, mapping to MITRE T1595 and T1083."
        ),
        mitre_techniques=["T1595", "T1083"],
        expected_rules=["WEB-001", "WEB-002"],
        target_decoy="WEB-001",
        estimated_events={"SMALL": 25, "MEDIUM": 100, "LARGE": 500},
    ),
    ScenarioType.SCENARIO_D: ScenarioMeta(
        scenario_id=ScenarioType.SCENARIO_D,
        title="Scenario D: Multi-Session Behavioral Association",
        description=(
            "Simulates a multi-stage adversary spanning multiple distinct sessions from a single origin IP. "
            "Triggers BEHAV-001 and exercises cross-session correlation graph mapping."
        ),
        mitre_techniques=["T1595", "T1110"],
        expected_rules=["BEHAV-001", "AUTH-001"],
        target_decoy="WEB-001",
        estimated_events={"SMALL": 25, "MEDIUM": 100, "LARGE": 500},
    ),
    ScenarioType.SCENARIO_E: ScenarioMeta(
        scenario_id=ScenarioType.SCENARIO_E,
        title="Scenario E: Analyst Investigation & Response Case",
        description=(
            "Demonstrates complete SOC analyst response: ingests attack telemetry, auto-generates alerts, "
            "creates a defensive response case, records analyst triage notes, and applies legal evidence hold."
        ),
        mitre_techniques=["T1110", "T1595"],
        expected_rules=["AUTH-001", "WEB-002"],
        target_decoy="WEB-001",
        estimated_events={"SMALL": 25, "MEDIUM": 100, "LARGE": 500},
    ),
    ScenarioType.SCENARIO_F: ScenarioMeta(
        scenario_id=ScenarioType.SCENARIO_F,
        title="Scenario F: Operational Resilience & Sandbox Recovery",
        description=(
            "Demonstrates self-monitoring and disaster recovery: simulates sensor heartbeat degradation, "
            "recovers sensor, generates cryptographic backup, and validates isolated sandbox database restore."
        ),
        mitre_techniques=["M1053"],  # Mitigation / Data Backup
        expected_rules=[],
        target_decoy="WEB-001",
        estimated_events={"SMALL": 25, "MEDIUM": 100, "LARGE": 500},
    ),
    ScenarioType.ALL: ScenarioMeta(
        scenario_id=ScenarioType.ALL,
        title="Full Spectrum Lab: Multi-Vector Benchmark",
        description=(
            "Simultaneous multi-vector composite benchmark running all attack vectors concurrently with "
            "background noise to measure platform throughput and detection quality."
        ),
        mitre_techniques=["T1110", "T1087", "T1595", "T1083"],
        expected_rules=["AUTH-001", "AUTH-003", "WEB-001", "WEB-002", "BEHAV-001"],
        target_decoy="WEB-001",
        estimated_events={"SMALL": 25, "MEDIUM": 100, "LARGE": 500},
    ),
}


def get_scenario_catalog() -> List[ScenarioMeta]:
    """Returns the ordered list of all demonstration scenario definitions."""
    return list(SCENARIO_CATALOG.values())

