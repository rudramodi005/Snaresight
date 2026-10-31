"""Deterministic Synthetic Telemetry Generator for SnareSight Demonstrations.

Generates privacy-compliant, deterministic synthetic honeypot interactions
strictly adhering to RFC 5737 test subnets, RFC 4122 UUIDs, and the Zero Password
Persistence Invariant.
"""

import hashlib
import random
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Tuple
from app.modules.demo.schemas import DatasetSize, ScenarioType

# RFC 5737 Test Subnets (Documentation and Demonstration Only)
TEST_IPS = [
    "198.51.100.45",
    "198.51.100.88",
    "198.51.100.120",
    "203.0.113.15",
    "203.0.113.42",
    "203.0.113.99",
    "192.0.2.10",
    "192.0.2.55",
]

BENIGN_PATHS = [
    "/",
    "/index.html",
    "/favicon.ico",
    "/static/css/main.css",
    "/static/js/bundle.js",
    "/api/v1/health",
    "/login",
    "/about",
    "/contact",
    "/products",
    "/documentation",
]

TRAVERSAL_PATHS = [
    "/../../etc/passwd",
    "/static/..%2f..%2fapp/config.json",
    "/view?file=..%2f..%2f..%2fetc%2fshadow",
    "/api/download?path=..\\..\\windows\\win.ini",
    "/assets/%2e%2e/%2e%2e/env.local",
    "/..%2F..%2Fetc%2Fhosts",
]

COMMON_USERNAMES = [
    "admin",
    "root",
    "administrator",
    "service_account",
    "deploy",
    "backup_operator",
    "analyst",
    "guest",
    "test_user",
    "webmaster",
]


class SyntheticTelemetryGenerator:
    """Generates synthetic, deterministic event streams for demonstration scenarios."""

    @classmethod
    def _hash_username(cls, username: str) -> str:
        """Computes deterministic privacy-safe SHA-256 fingerprint for a username."""
        return hashlib.sha256(f"demo_salt_{username}".encode("utf-8")).hexdigest()

    @classmethod
    def _generate_session_id(cls, prng: random.Random) -> str:
        """Generates a valid decoy session ID matching regex ^decoy_sess_[a-f0-9]{32}$."""
        token = uuid.UUID(int=prng.getrandbits(128)).hex
        return f"decoy_sess_{token}"

    @classmethod
    def generate_events(
        cls,
        scenario_type: ScenarioType,
        size: DatasetSize,
        seed: int = 42,
        target_decoy_id: str = "WEB-001",
        source_ip_override: str | None = None,
        run_id: str | None = None,
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Generates a batch of synthetic events and ground-truth metadata.
        
        Returns:
            (events_list, ground_truth_manifest)
        """
        prng = random.Random(seed)
        run_id = run_id or f"run_{uuid.UUID(int=prng.getrandbits(128)).hex[:8]}"

        # Determine target count based on dataset size
        if size == DatasetSize.SMALL:
            total_target = 25
        elif size == DatasetSize.MEDIUM:
            total_target = 100
        else:
            total_target = 500

        now_utc = datetime.now(timezone.utc)
        base_time = now_utc - timedelta(minutes=5)

        events: List[Dict[str, Any]] = []
        ground_truth: Dict[str, Any] = {
            "run_id": run_id,
            "scenario_type": scenario_type.value,
            "seed": seed,
            "total_generated": 0,
            "attack_events_count": 0,
            "benign_events_count": 0,
            "expected_rules": [],
            "ground_truth_map": {},  # raw_event_id -> {is_attack: bool, expected_rule: str | None}
        }

        # ---------------------------------------------------------------------
        # SCENARIO A: Repeated Login Failures (AUTH-001)
        # ---------------------------------------------------------------------
        if scenario_type == ScenarioType.SCENARIO_A:
            ground_truth["expected_rules"] = ["AUTH-001"]
            attacker_ip = source_ip_override or TEST_IPS[0]
            attacker_session = cls._generate_session_id(prng)
            attack_count = min(8, total_target)
            benign_count = total_target - attack_count

            # Attack Events: repeated failed logins in same session
            user_fingerprint = cls._hash_username("admin")
            for i in range(attack_count):
                ev_id = str(uuid.UUID(int=prng.getrandbits(128), version=4))
                obs_time = base_time + timedelta(seconds=i * 10)
                event = {
                    "raw_event_id": ev_id,
                    "schema_version": "1.0",
                    "event_type": "web_login_attempt",
                    "event_category": "authentication",
                    "decoy_id": target_decoy_id,
                    "observed_at": obs_time.isoformat(),
                    "session_id": attacker_session,
                    "source": {
                        "ip_address": attacker_ip,
                        "port": prng.randint(40000, 65000),
                        "protocol": "https",
                    },
                    "interaction": {
                        "username_fingerprint": user_fingerprint,
                        "password_present": True,
                        "status_code": 401,
                    },
                    "provenance": {
                        "source_type": "synthetic_simulation",
                        "environment": "isolated_lab",
                        "is_synthetic": True,
                        "scenario_id": "SCENARIO_A",
                        "run_id": run_id,
                    },
                }
                events.append(event)
                ground_truth["ground_truth_map"][ev_id] = {
                    "is_attack": True,
                    "expected_rule": "AUTH-001",
                    "session_id": attacker_session,
                }
                ground_truth["attack_events_count"] += 1

            # Benign background noise across separate sessions
            for i in range(benign_count):
                ev_id = str(uuid.UUID(int=prng.getrandbits(128), version=4))
                obs_time = base_time + timedelta(seconds=attack_count * 10 + i * 5)
                b_sess = cls._generate_session_id(prng)
                b_ip = prng.choice(TEST_IPS[1:])
                event = {
                    "raw_event_id": ev_id,
                    "schema_version": "1.0",
                    "event_type": "http_request",
                    "event_category": "request",
                    "decoy_id": target_decoy_id,
                    "observed_at": obs_time.isoformat(),
                    "session_id": b_sess,
                    "source": {
                        "ip_address": b_ip,
                        "port": prng.randint(40000, 65000),
                        "protocol": "https",
                    },
                    "interaction": {
                        "http_method": "GET",
                        "http_path": prng.choice(BENIGN_PATHS),
                        "status_code": 200,
                    },
                    "provenance": {
                        "source_type": "synthetic_simulation",
                        "environment": "isolated_lab",
                        "is_synthetic": True,
                        "scenario_id": "SCENARIO_A",
                        "run_id": run_id,
                    },
                }
                events.append(event)
                ground_truth["ground_truth_map"][ev_id] = {
                    "is_attack": False,
                    "expected_rule": None,
                    "session_id": b_sess,
                }
                ground_truth["benign_events_count"] += 1

        # ---------------------------------------------------------------------
        # SCENARIO B: Username Enumeration Probing (AUTH-003)
        # ---------------------------------------------------------------------
        elif scenario_type == ScenarioType.SCENARIO_B:
            ground_truth["expected_rules"] = ["AUTH-003"]
            attacker_ip = source_ip_override or TEST_IPS[1]
            attacker_session = cls._generate_session_id(prng)
            attack_count = min(10, total_target)
            benign_count = total_target - attack_count

            # Attack Events: probing multiple distinct usernames
            for i in range(attack_count):
                ev_id = str(uuid.UUID(int=prng.getrandbits(128), version=4))
                obs_time = base_time + timedelta(seconds=i * 8)
                username = COMMON_USERNAMES[i % len(COMMON_USERNAMES)]
                event = {
                    "raw_event_id": ev_id,
                    "schema_version": "1.0",
                    "event_type": "web_login_attempt",
                    "event_category": "authentication",
                    "decoy_id": target_decoy_id,
                    "observed_at": obs_time.isoformat(),
                    "session_id": attacker_session,
                    "source": {
                        "ip_address": attacker_ip,
                        "port": prng.randint(40000, 65000),
                        "protocol": "https",
                    },
                    "interaction": {
                        "username_fingerprint": cls._hash_username(username),
                        "password_present": True,
                        "status_code": 401,
                    },
                    "provenance": {
                        "source_type": "synthetic_simulation",
                        "environment": "isolated_lab",
                        "is_synthetic": True,
                        "scenario_id": "SCENARIO_B",
                        "run_id": run_id,
                    },
                }
                events.append(event)
                ground_truth["ground_truth_map"][ev_id] = {
                    "is_attack": True,
                    "expected_rule": "AUTH-003",
                    "session_id": attacker_session,
                }
                ground_truth["attack_events_count"] += 1

            for i in range(benign_count):
                ev_id = str(uuid.UUID(int=prng.getrandbits(128), version=4))
                obs_time = base_time + timedelta(seconds=attack_count * 8 + i * 5)
                b_sess = cls._generate_session_id(prng)
                event = {
                    "raw_event_id": ev_id,
                    "schema_version": "1.0",
                    "event_type": "http_request",
                    "event_category": "request",
                    "decoy_id": target_decoy_id,
                    "observed_at": obs_time.isoformat(),
                    "session_id": b_sess,
                    "source": {
                        "ip_address": prng.choice(TEST_IPS[2:]),
                        "port": prng.randint(40000, 65000),
                        "protocol": "https",
                    },
                    "interaction": {
                        "http_method": "GET",
                        "http_path": prng.choice(BENIGN_PATHS),
                        "status_code": 200,
                    },
                    "provenance": {
                        "source_type": "synthetic_simulation",
                        "environment": "isolated_lab",
                        "is_synthetic": True,
                        "scenario_id": "SCENARIO_B",
                        "run_id": run_id,
                    },
                }
                events.append(event)
                ground_truth["ground_truth_map"][ev_id] = {
                    "is_attack": False,
                    "expected_rule": None,
                    "session_id": b_sess,
                }
                ground_truth["benign_events_count"] += 1

        # ---------------------------------------------------------------------
        # SCENARIO C: Suspicious Web Path Requests (WEB-001 & WEB-002)
        # ---------------------------------------------------------------------
        elif scenario_type == ScenarioType.SCENARIO_C:
            ground_truth["expected_rules"] = ["WEB-001", "WEB-002"]
            attacker_ip = source_ip_override or TEST_IPS[2]
            attacker_session = cls._generate_session_id(prng)
            traversal_count = min(6, total_target)
            enum_count = min(6, max(0, total_target - traversal_count))
            benign_count = total_target - traversal_count - enum_count

            # 1. Directory Traversal Probes (WEB-002)
            for i in range(traversal_count):
                ev_id = str(uuid.UUID(int=prng.getrandbits(128), version=4))
                obs_time = base_time + timedelta(seconds=i * 6)
                path = TRAVERSAL_PATHS[i % len(TRAVERSAL_PATHS)]
                event = {
                    "raw_event_id": ev_id,
                    "schema_version": "1.0",
                    "event_type": "http_request",
                    "event_category": "request",
                    "decoy_id": target_decoy_id,
                    "observed_at": obs_time.isoformat(),
                    "session_id": attacker_session,
                    "source": {
                        "ip_address": attacker_ip,
                        "port": prng.randint(40000, 65000),
                        "protocol": "https",
                    },
                    "interaction": {
                        "http_method": "GET",
                        "http_path": path,
                        "status_code": 404,
                    },
                    "provenance": {
                        "source_type": "synthetic_simulation",
                        "environment": "isolated_lab",
                        "is_synthetic": True,
                        "scenario_id": "SCENARIO_C",
                        "run_id": run_id,
                    },
                }
                events.append(event)
                ground_truth["ground_truth_map"][ev_id] = {
                    "is_attack": True,
                    "expected_rule": "WEB-002",
                    "session_id": attacker_session,
                }
                ground_truth["attack_events_count"] += 1

            # 2. Distinct Web Path Probing (WEB-001)
            for i in range(enum_count):
                ev_id = str(uuid.UUID(int=prng.getrandbits(128), version=4))
                obs_time = base_time + timedelta(seconds=(traversal_count + i) * 6)
                path = f"/api/v1/internal_test_endpoint_{i}"
                event = {
                    "raw_event_id": ev_id,
                    "schema_version": "1.0",
                    "event_type": "http_request",
                    "event_category": "request",
                    "decoy_id": target_decoy_id,
                    "observed_at": obs_time.isoformat(),
                    "session_id": attacker_session,
                    "source": {
                        "ip_address": attacker_ip,
                        "port": prng.randint(40000, 65000),
                        "protocol": "https",
                    },
                    "interaction": {
                        "http_method": "GET",
                        "http_path": path,
                        "status_code": 404,
                    },
                    "provenance": {
                        "source_type": "synthetic_simulation",
                        "environment": "isolated_lab",
                        "is_synthetic": True,
                        "scenario_id": "SCENARIO_C",
                        "run_id": run_id,
                    },
                }
                events.append(event)
                ground_truth["ground_truth_map"][ev_id] = {
                    "is_attack": True,
                    "expected_rule": "WEB-001",
                    "session_id": attacker_session,
                }
                ground_truth["attack_events_count"] += 1

            # Benign background
            for i in range(benign_count):
                ev_id = str(uuid.UUID(int=prng.getrandbits(128), version=4))
                obs_time = base_time + timedelta(seconds=(traversal_count + enum_count + i) * 5)
                b_sess = cls._generate_session_id(prng)
                event = {
                    "raw_event_id": ev_id,
                    "schema_version": "1.0",
                    "event_type": "http_request",
                    "event_category": "request",
                    "decoy_id": target_decoy_id,
                    "observed_at": obs_time.isoformat(),
                    "session_id": b_sess,
                    "source": {
                        "ip_address": prng.choice(TEST_IPS[3:]),
                        "port": prng.randint(40000, 65000),
                        "protocol": "https",
                    },
                    "interaction": {
                        "http_method": "GET",
                        "http_path": prng.choice(BENIGN_PATHS),
                        "status_code": 200,
                    },
                    "provenance": {
                        "source_type": "synthetic_simulation",
                        "environment": "isolated_lab",
                        "is_synthetic": True,
                        "scenario_id": "SCENARIO_C",
                        "run_id": run_id,
                    },
                }
                events.append(event)
                ground_truth["ground_truth_map"][ev_id] = {
                    "is_attack": False,
                    "expected_rule": None,
                    "session_id": b_sess,
                }
                ground_truth["benign_events_count"] += 1

        # ---------------------------------------------------------------------
        # SCENARIO D: Multi-Session Behavioral Association (BEHAV-001)
        # ---------------------------------------------------------------------
        elif scenario_type == ScenarioType.SCENARIO_D:
            ground_truth["expected_rules"] = ["BEHAV-001", "AUTH-001"]
            shared_attacker_ip = source_ip_override or TEST_IPS[4]
            session_1 = cls._generate_session_id(prng)
            session_2 = cls._generate_session_id(prng)

            attack_count_s1 = min(4, total_target // 2)
            attack_count_s2 = min(4, total_target // 2)
            benign_count = total_target - attack_count_s1 - attack_count_s2

            # Session 1: Reconnaissance (Web Path Discovery)
            for i in range(attack_count_s1):
                ev_id = str(uuid.UUID(int=prng.getrandbits(128), version=4))
                obs_time = base_time + timedelta(seconds=i * 8)
                event = {
                    "raw_event_id": ev_id,
                    "schema_version": "1.0",
                    "event_type": "http_request",
                    "event_category": "request",
                    "decoy_id": target_decoy_id,
                    "observed_at": obs_time.isoformat(),
                    "session_id": session_1,
                    "source": {
                        "ip_address": shared_attacker_ip,
                        "port": prng.randint(40000, 65000),
                        "protocol": "https",
                    },
                    "interaction": {
                        "http_method": "GET",
                        "http_path": f"/portal/internal_admin_{i}",
                        "status_code": 403,
                    },
                    "provenance": {
                        "source_type": "synthetic_simulation",
                        "environment": "isolated_lab",
                        "is_synthetic": True,
                        "scenario_id": "SCENARIO_D",
                        "run_id": run_id,
                    },
                }
                events.append(event)
                ground_truth["ground_truth_map"][ev_id] = {
                    "is_attack": True,
                    "expected_rule": "BEHAV-001",
                    "session_id": session_1,
                }
                ground_truth["attack_events_count"] += 1

            # Session 2: Credential Guessing from Same Attacker IP
            for i in range(attack_count_s2):
                ev_id = str(uuid.UUID(int=prng.getrandbits(128), version=4))
                obs_time = base_time + timedelta(seconds=(attack_count_s1 * 8) + i * 8)
                event = {
                    "raw_event_id": ev_id,
                    "schema_version": "1.0",
                    "event_type": "web_login_attempt",
                    "event_category": "authentication",
                    "decoy_id": target_decoy_id,
                    "observed_at": obs_time.isoformat(),
                    "session_id": session_2,
                    "source": {
                        "ip_address": shared_attacker_ip,
                        "port": prng.randint(40000, 65000),
                        "protocol": "https",
                    },
                    "interaction": {
                        "username_fingerprint": cls._hash_username("root"),
                        "password_present": True,
                        "status_code": 401,
                    },
                    "provenance": {
                        "source_type": "synthetic_simulation",
                        "environment": "isolated_lab",
                        "is_synthetic": True,
                        "scenario_id": "SCENARIO_D",
                        "run_id": run_id,
                    },
                }
                events.append(event)
                ground_truth["ground_truth_map"][ev_id] = {
                    "is_attack": True,
                    "expected_rule": "AUTH-001",
                    "session_id": session_2,
                }
                ground_truth["attack_events_count"] += 1

            # Benign background
            for i in range(benign_count):
                ev_id = str(uuid.UUID(int=prng.getrandbits(128), version=4))
                obs_time = base_time + timedelta(seconds=120 + i * 5)
                b_sess = cls._generate_session_id(prng)
                event = {
                    "raw_event_id": ev_id,
                    "schema_version": "1.0",
                    "event_type": "http_request",
                    "event_category": "request",
                    "decoy_id": target_decoy_id,
                    "observed_at": obs_time.isoformat(),
                    "session_id": b_sess,
                    "source": {
                        "ip_address": prng.choice(TEST_IPS[5:]),
                        "port": prng.randint(40000, 65000),
                        "protocol": "https",
                    },
                    "interaction": {
                        "http_method": "GET",
                        "http_path": prng.choice(BENIGN_PATHS),
                        "status_code": 200,
                    },
                    "provenance": {
                        "source_type": "synthetic_simulation",
                        "environment": "isolated_lab",
                        "is_synthetic": True,
                        "scenario_id": "SCENARIO_D",
                        "run_id": run_id,
                    },
                }
                events.append(event)
                ground_truth["ground_truth_map"][ev_id] = {
                    "is_attack": False,
                    "expected_rule": None,
                    "session_id": b_sess,
                }
                ground_truth["benign_events_count"] += 1

        # ---------------------------------------------------------------------
        # SCENARIO E, F, or ALL
        # ---------------------------------------------------------------------
        else:
            # Composite blend across all types
            ground_truth["expected_rules"] = ["AUTH-001", "AUTH-003", "WEB-001", "WEB-002", "BEHAV-001"]
            sub_count = max(4, total_target // 4)
            evs_a, gt_a = cls.generate_events(ScenarioType.SCENARIO_A, DatasetSize.SMALL, seed + 1, target_decoy_id, run_id=run_id)
            evs_b, gt_b = cls.generate_events(ScenarioType.SCENARIO_B, DatasetSize.SMALL, seed + 2, target_decoy_id, run_id=run_id)
            evs_c, gt_c = cls.generate_events(ScenarioType.SCENARIO_C, DatasetSize.SMALL, seed + 3, target_decoy_id, run_id=run_id)
            evs_d, gt_d = cls.generate_events(ScenarioType.SCENARIO_D, DatasetSize.SMALL, seed + 4, target_decoy_id, run_id=run_id)

            combined_events = (evs_a + evs_b + evs_c + evs_d)[:total_target]
            events.extend(combined_events)
            for ev in combined_events:
                eid = ev["raw_event_id"]
                gt_meta = (
                    gt_a["ground_truth_map"].get(eid)
                    or gt_b["ground_truth_map"].get(eid)
                    or gt_c["ground_truth_map"].get(eid)
                    or gt_d["ground_truth_map"].get(eid)
                )
                if gt_meta:
                    ground_truth["ground_truth_map"][eid] = gt_meta
                    if gt_meta["is_attack"]:
                        ground_truth["attack_events_count"] += 1
                    else:
                        ground_truth["benign_events_count"] += 1

        ground_truth["total_generated"] = len(events)
        return events, ground_truth

