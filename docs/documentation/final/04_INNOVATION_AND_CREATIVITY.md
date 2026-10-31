# Evaluation Criterion 4: Innovation & Creative Technical Contributions

**Document Version:** 1.0.0  
**Phase:** 8 — Testing, Demonstration & Project Handover  
**Document:** `docs/final/04_INNOVATION_AND_CREATIVITY.md`  
**Evaluation Weight:** 20% (Equal Weighting)  

---

## 1. Contextual Definition of Innovation in SnareSight

In academic and applied engineering contexts, innovation does not require inventing novel mathematical cryptography or claiming unprecedented global discoveries. Rather, SnareSight's innovation lies in its **creative synthesis of cyber deception, deterministic threat detection, graph-based session correlation, and evidence-grounded MITRE ATT&CK mapping into a unified, privacy-conscious SOC platform**.

Below, each verified capability is analyzed using a rigorous 6-point evaluation framework.

---

## 2. In-Depth Evaluation of 8 Differentiating Capabilities

### 2.1 Decoupled Severity vs Confidence Dual-Metric Scoring
1. **Underlying Idea:** Decouple the *potential impact* of an attack from the *evidentiary certainty* of its observation.
2. **Practical Benefit:** Eliminates false-positive skew. A loud reconnaissance port scan can have 95% Confidence (unmistakable automated traffic) but only 30% Severity (low impact on assets), preventing unnecessary Tier-1 analyst paging.
3. **Implementation:** Implemented in `backend/app/detection/scoring_policy.py`. Computes independent integer scores $[0, 100]$.
4. **Concrete Evidence:** Test suite `tests/test_demo_api.py` verifies distinct output scores across all synthetic attack scenarios.
5. **Difference from Basic Tools:** Basic honeypots (e.g. Cowrie or Dionaea) output simple text logs with zero impact/confidence scoring. Generic SIEMs apply arbitrary flat alert severities.
6. **Known Limitations:** Scoring weights are currently calibrated via static rules; they do not automatically adapt to changing internal network topologies without administrative re-tuning.

---

### 2.2 Evidence-Grounded MITRE ATT&CK Mapping with Human Review Gate
1. **Underlying Idea:** Prohibit speculative technique mapping by requiring concrete forensic evidence before associating telemetry with an ATT&CK technique, while providing an analyst verification gate.
2. **Practical Benefit:** Prevents "matrix painting" (filling out the ATT&CK matrix based on theoretical threat intelligence rather than actual observed telemetry).
3. **Implementation:** Implemented in `backend/app/modules/mitre/` with database junction tables (`attack_detection_mappings`, `attack_mapping_evidence`, `attack_mapping_reviews`).
4. **Concrete Evidence:** Verified in `tests/modules/mitre/test_api.py`. Endpoint `/api/v1/attack/techniques/{id}/evidence` returns the exact raw event records that justified the mapping.
5. **Difference from Basic Tools:** Traditional dashboards either lack MITRE mapping entirely or apply hardcoded tags that cannot be inspected, challenged, or audited by analysts.
6. **Known Limitations:** Coverage is currently limited to the techniques represented in the 10 catalogue detection rules and synthetic demonstration scenarios.

---

### 2.3 Interactive Attack-Chain Graph Reconstruction (React Flow DAG)
1. **Underlying Idea:** Automatically assemble disconnected temporal events into an interactive, chronological directed acyclic graph (DAG) representing intruder stage progression.
2. **Practical Benefit:** Allows SOC analysts to instantly visualize the entire intrusion narrative (e.g. `Reconnaissance` $\to$ `Discovery` $\to$ `Credential Access` $\to$ `Execution`) without manually searching through thousands of raw syslog rows.
3. **Implementation:** Implemented in `frontend/src/pages/AttackChains/` using React Flow, linked to backend sequence API `/api/v1/sequences/{id}`.
4. **Concrete Evidence:** Verified in frontend unit test `tests/unit/components.test.ts` and demonstrated in Scenario F of the Demo Lab.
5. **Difference from Basic Tools:** Most honeypot interfaces provide simple tabular event lists. SnareSight reconstructs the relational state machine of the attacker's journey.
6. **Known Limitations:** Highly distributed attacks spanning weeks with variable IP addresses require heuristic clustering to link properly into a single chain.

---

### 2.4 Salted SHA-256 Zero-Password Invariant & Privacy Redaction
1. **Underlying Idea:** Enforce programmatic data protection by intercepting and redacting captured credentials *prior* to database insertion, while preserving cryptographic hashes for dictionary-attack clustering.
2. **Practical Benefit:** Complies with data protection standards (GDPR, ISO 27001). If the SnareSight database is compromised, captured passwords cannot be leaked or weaponized.
3. **Implementation:** Implemented in `backend/app/detection/field_registry.py` and `app.api.ingestion`.
4. **Concrete Evidence:** Verified in backend test `test_telemetry_to_alert_pipeline`: raw payload `password=Password123!` is stored as `password=[REDACTED]` with matching SHA-256 hash.
5. **Difference from Basic Tools:** Standard honeypots store credentials in plaintext flat files (e.g. `user:password`), creating an internal security liability.
6. **Known Limitations:** Very short dictionary words (e.g. `123456`) could theoretically be matched via pre-computed rainbow tables; mitigated by adding unique installation salts.

---

### 2.5 Explainable Source Profiling & Behavioral Similarity Clustering
1. **Underlying Idea:** Build longitudinal dossiers on attacking IP addresses based on observed tradecraft, calculating dynamic threat scores and identifying similar threat actors through behavioral fingerprints.
2. **Practical Benefit:** Shifts the analyst's focus from individual alerts to persistent threat entities, revealing whether an IP is an opportunistic scanner or a targeted persistent probe.
3. **Implementation:** Implemented in `backend/app/modules/source_intelligence/service.py` and `routes.py`.
4. **Concrete Evidence:** Verified in `tests/modules/source_intelligence/test_api.py`. Returns behavioral tags (`BRUTE_FORCER`, `RECON_SCANNER`) and Jaccard similarity scores.
5. **Difference from Basic Tools:** Typical log viewers treat every IP query independently. SnareSight computes lifetime recurrence, port diversity, and tool signatures.
6. **Known Limitations:** Source profiles cluster network-layer indicators; they do not prove the physical identity of human threat actors (explicitly disclosed in analysis caveats).

---

### 2.6 Analyst-in-the-Loop Defensive Containment Generation
1. **Underlying Idea:** Automatically transform validated threat intelligence into ready-to-deploy firewall containment scripts (`iptables`, `UFW`, AWS Security Groups) within the incident case workspace.
2. **Practical Benefit:** Reduces Mean Time to Respond (MTTR) from hours to seconds while preventing accidental network lockout through human approval gates.
3. **Implementation:** Implemented in `backend/app/modules/response/service.py` (`generate_containment_action`).
4. **Concrete Evidence:** Verified in `tests/test_e2e_workflows.py::test_incident_case_and_containment`. Generates validated CLI blocking commands.
5. **Difference from Basic Tools:** Honeypots passively record attacks with zero containment integration. SnareSight bridges the gap between deception intelligence and perimeter enforcement.
6. **Known Limitations:** Does not automatically execute scripts on production boundary routers; human analyst copy-paste or approval is required by design.

---

### 2.7 Automated Disaster Recovery & Dry-Run Restore Validation
1. **Underlying Idea:** Protect platform integrity by automatically executing isolated, in-memory dry-run restore tests against generated database backup snapshots.
2. **Practical Benefit:** Guarantees that backups are not corrupted and can actually be restored during a critical infrastructure disaster.
3. **Implementation:** Implemented in `backend/app/modules/resilience/backup_service.py` (`test_restore_archive`).
4. **Concrete Evidence:** Verified in `tests/modules/resilience/test_api.py`. Decompresses backup, verifies table counts, and audits execution duration.
5. **Difference from Basic Tools:** Academic security projects rarely implement automated backup checksums and restore validation.
6. **Known Limitations:** Tests restore schema and structure; does not simulate full multi-terabyte enterprise database recovery.

---

### 2.8 Deterministic Demonstration Lab with Quality Evaluation Harness
1. **Underlying Idea:** Provide a self-contained demonstration environment (`/demo`) executing 6 reproducible synthetic attack scenarios and measuring detection precision, recall, and F1-score.
2. **Practical Benefit:** Enables mentors, evaluators, and reviewers to verify the complete end-to-end platform safely in an isolated lab without requiring external network connectivity or real exploits.
3. **Implementation:** Implemented in `backend/app/modules/demo/` and `frontend/src/features/demo/`.
4. **Concrete Evidence:** 11/11 tests passing in `tests/test_demo_api.py`. Evaluates detection precision ($100\%$) and recall ($100\%$) on synthetic suites.
5. **Difference from Basic Tools:** Most security project demonstrations rely on fragile manual scripts or video recordings. SnareSight builds the evaluation harness directly into the application.
6. **Known Limitations:** Synthetic scenarios are deterministic; real-world adversary traffic exhibits greater noise and timing jitter.

