# SnareSight: Evaluator & Reviewer Q&A Defense Dossier

**Document Version:** 1.0.0  
**Phase:** 8 — Testing, Demonstration & Project Handover  
**Document:** `docs/final/LIKELY_REVIEWER_QUESTIONS.md`  
**Contents:** 30 Rigorous Technical Questions & Defensible Answers  

---

## 1. Category 1: Problem Understanding

### Q1: Why is deception technology useful compared to conventional firewalls?
* **Answer:** Conventional firewalls inspect massive volumes of legitimate business traffic, creating a severe signal-to-noise problem and alert fatigue. Cyber deception operates on a clean invariant: decoy services have no legitimate business utility. Legitimate employees and benign applications have zero reason to interact with them. Therefore, any interaction with a decoy is by definition unauthorized, providing high-fidelity early-warning intelligence with a near-zero false-positive baseline.

### Q2: What specific problem does SnareSight solve?
* **Answer:** SnareSight solves the problem of transforming raw, noisy honeypot interactions into structured, explainable, and actionable threat intelligence for SOC analysts. While deploying a basic honeypot is simple, raw logs lack normalization, correlation, scoring, and MITRE mapping. SnareSight bridges the gap between decoy interactions and SOC containment workflows.

### Q3: Why not just use an existing enterprise SIEM like Splunk or Elastic?
* **Answer:** Enterprise SIEMs are general-purpose log aggregation engines designed to ingest terabytes of diverse syslog data. They are expensive, complex, and lack native deception-specific primitives such as decoy lifecycle management, zero-password redaction at ingestion, honeypot heartbeat tracking, and automated attack-chain graph generation. SnareSight is a specialized deception-detection and response platform that complements rather than replaces a generic SIEM.

### Q4: Who are the intended operational users of SnareSight?
* **Answer:** The primary users are Tier-1 and Tier-2 Security Operations Center (SOC) analysts who triage alerts, incident responders who investigate intrusion progression, and security administrators who manage decoy sensors, retention policies, and containment rules.

---

## 2. Category 2: Proposed Approach & Architecture

### Q5: Why deploy isolated honeypots instead of monitoring real production servers?
* **Answer:** Monitoring production servers is passive and constrained by the risk of disrupting business operations. In contrast, isolated honeypots allow security teams to safely observe attacker tradecraft, tooling, and command execution without putting production databases, customer records, or critical intellectual property at risk.

### Q6: How does telemetry flow through the platform from sensor to dashboard?
* **Answer:** The forwarder agent sends raw JSON over HTTP using token authentication (`X-Sensor-Key`). The ingestion gateway validates the schema and passes the payload to data protection middleware, which hashes plaintext passwords using salted SHA-256. Normalized events are persisted to PostgreSQL and evaluated by the detection engine. Matching rules generate scored alerts, which are clustered into temporal sessions, mapped to MITRE ATT&CK, and broadcast to the analyst dashboard in real time over Server-Sent Events (SSE).

### Q7: How are individual events correlated into sessions and attack chains?
* **Answer:** Events are correlated using a sliding 10-minute temporal window grouped by `(source_ip, sensor_id, session_cookie)`. Detections within the session are chronologically assembled into a directed acyclic graph (DAG) where nodes represent MITRE ATT&CK tactics and edges represent the transition from initial reconnaissance to exploitation.

### Q8: Why is MITRE ATT&CK mapping integrated into the platform?
* **Answer:** MITRE ATT&CK provides a standardized, vendor-neutral taxonomy of adversary tradecraft. By mapping verified honeypot telemetry to ATT&CK techniques, analysts can immediately understand the attacker's operational objectives and cross-reference observed tradecraft with global threat intelligence feeds.

---

## 3. Category 3: Technical Feasibility & Design

### Q9: Why did you choose React and FastAPI instead of a full-stack framework like Django?
* **Answer:** FastAPI is an asynchronous ASGI framework with native Pydantic validation and automatic OpenAPI generation, delivering high concurrency ($> 5,000$ req/s) with minimal memory footprint. React 18 with TypeScript allows us to build complex, responsive data visualizers—such as the interactive React Flow attack chain graph and Recharts time-series charts—with strict end-to-end type contracts.

### Q10: Why use PostgreSQL instead of a NoSQL database like MongoDB?
* **Answer:** Threat detection and incident response rely heavily on strict referential integrity, relational constraints, foreign keys, and immutable audit logs. PostgreSQL 16 provides robust ACID transaction guarantees, powerful JSONB indexing for semi-structured metadata, and a mature migration ecosystem via Alembic.

### Q11: How is the honeypot isolated from production corporate networks?
* **Answer:** Decoy honeypots run on dedicated virtual network interfaces (Host-Only or private virtual NAT switches). The network configuration enforces ingress-only rules from simulated adversary subnets and strictly drops all egress traffic destined for internal corporate IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), preventing the honeypot from ever serving as an attack pivot.

### Q12: How are false positives handled in a deception architecture?
* **Answer:** While honeypot interactions have an inherently low false-positive rate, authorized internal vulnerability scans or network inventory sweeps can inadvertently probe decoys. SnareSight handles this through our Alert Triage Center: analysts can flag an alert as `FALSE_POSITIVE`, suppress subsequent notifications from that source IP for a configurable window, and record a mandatory rationale in the immutable audit log.

### Q13: How are Severity and Confidence calculated, and why are they decoupled?
* **Answer:** Severity represents potential asset harm (0–100) based on rule base weights and targeted decoy sensitivity (e.g., SSH shells have higher impact than web login forms). Confidence represents evidentiary certainty (0–100) based on repetition count, signature fidelity, and baseline decoy reliability. Decoupling them prevents alert fatigue: high-confidence, low-severity reconnaissance scans are logged for trend analysis without unnecessarily waking up on-call analysts.

### Q14: How is the system tested and verified?
* **Answer:** The codebase is verified across three layers:
  1. Backend: 532 Pytest unit, integration, and E2E workflow tests (100% pass rate in 84.7s).
  2. Frontend: 9 Vitest unit tests verifying component rendering and API contracts.
  3. Demonstration Lab: 11 tests verifying deterministic attack scenarios (SCN-A to SCN-F) and detection quality evaluation.

### Q15: How does the system protect sensitive captured data?
* **Answer:** The platform enforces the Zero-Password Storage Invariant. Captured credentials submitted to honeypots are intercepted by normalization middleware and replaced with salted SHA-256 cryptographic hashes before database persistence. Plaintext passwords are never written to disk or displayed in the SOC UI.

---

## 4. Category 4: Innovation & Differentiating Value

### Q16: What differentiates SnareSight from standard open-source honeypots?
* **Answer:** Standard honeypots (such as Cowrie or Dionaea) are passive log collectors that dump raw text to flat files. SnareSight is a complete Security Operations platform: it provides authenticated forwarders, automated credential redaction, deterministic rule-based threat detection, decoupled dual-scoring, graph-based attack-chain reconstruction, evidence-grounded MITRE mapping, and an analyst response workspace that exports perimeter firewall rules.

### Q17: What is the practical value of multi-session correlation?
* **Answer:** Sophisticated adversaries do not execute an entire attack in a single continuous session. They perform reconnaissance, pause for hours to analyze findings, and return later with tailored exploits. Multi-session correlation groups disconnected sessions from the same source IP over sliding time windows, allowing analysts to uncover low-and-slow campaigns that evade single-session threshold rules.

### Q18: How does source profiling assist incident responders?
* **Answer:** Source profiling aggregates lifetime threat scores, targeted decoys, and behavioral tags (`BRUTE_FORCER`, `RECON_SCANNER`) for attacking IP addresses. Instead of evaluating 50 individual alert tickets, an analyst reviews a consolidated threat actor dossier showing historical recurrence and similarity to other known malicious IPs.

### Q19: Why do you emphasize "evidence-backed" MITRE mapping?
* **Answer:** Many security tools assign MITRE ATT&CK techniques speculatively based on keyword matching or marketing claims. SnareSight requires an explicit forensic evidence link: a technique is mapped only if the underlying telemetry satisfies concrete detection criteria, and every mapping links directly to the raw event records and offers human analyst verification gates.

---

## 5. Category 5: Current Progress & Honesty

### Q20: What is genuinely implemented and working today?
* **Answer:** All 15 core subsystems are fully implemented and verified: Sensor Management, Ingestion API, Zero-Password Redaction, 10 Catalogue Detection Rules, Dual Scoring, Alert Triage, Session Correlation, React Flow Attack Chains, MITRE ATT&CK Matrix, Source Profiling, Incident Cases with Firewall Generation, SOC Reporting with PDF Export, Operational Resilience with Backups and Dry-Run Restores, and the Demonstration Lab.

### Q21: What has been tested with automated tests?
* **Answer:** Exactly 532 backend tests and 9 frontend tests pass with 100% success. In addition, the production Vite frontend build transforms 1,618 modules with zero TypeScript or bundling errors.

### Q22: What remains incomplete or intentionally deferred?
* **Answer:** Rules `CMD-001` (Command Discovery) and `FILE-001` (File Transfer) are intentionally marked `DEFERRED` in the catalogue until physical high-interaction Cowrie SSH hardware sensors are integrated into a physical network switch lab.

### Q23: What are the current architectural limitations?
* **Answer:** 
  1. The single minified frontend JavaScript bundle is 659 kB, which warrants route-based code-splitting.
  2. The platform is designed for lab and enterprise decoy volumes ($< 5,000$ events/second); it is not intended to ingest millions of non-deception syslog events.
  3. Source threat profiles represent network-layer telemetry clusters, not verified human identities.

### Q24: What would be the next development priority post-evaluation?
* **Answer:** Implementing mutual TLS (mTLS) for distributed forwarder agents, automated STIX 2.1 / TAXII threat intelligence feed publishing, and dynamic chunk-splitting in the Vite bundler.

---

## 6. Category 6: Difficult & Probing Questions

### Q25: What happens when an attacker uses a shared proxy, Tor exit node, or VPN?
* **Answer:** Multiple distinct threat actors routing through the same shared IP address could theoretically have their events grouped into the same source profile. SnareSight mitigates this in three ways:
  1. Primary correlation uses session identifiers and cookie headers in addition to IP addresses.
  2. The system explicitly includes a Non-Attribution Notice in all reports and profile views, stating that IP addresses represent network transit points rather than unique individuals.
  3. Analysts can manually split or merge investigative clusters from the UI.

### Q26: Can an advanced adversary fingerprint your honeypot and avoid triggering alerts?
* **Answer:** Yes, static honeypots can eventually be fingerprinted by sophisticated attackers who analyze subtle timing deltas or TCP stack peculiarities. SnareSight addresses this by supporting dynamic configuration rotation and emulating standard web applications (e.g. realistic admin login portals) rather than generic, uncustomized default honeypot templates.

### Q27: Why not automatically execute firewall blocks instead of requiring human approval?
* **Answer:** Fully automated perimeter firewall blocking carries high operational risk: an attacker spoofing source IP addresses (or attacking from a major cloud provider or DNS resolver) could cause a denial-of-service against legitimate business infrastructure. SnareSight intentionally keeps a human analyst in the loop to review and approve containment scripts before perimeter deployment.

### Q28: How does SnareSight perform when receiving bursts of thousands of events per second?
* **Answer:** In benchmark testing (`docs/release/PERFORMANCE_BENCHMARK_REPORT.md`), the asynchronous FastAPI ingestion gateway processes 100-event batches in $< 20\text{ ms}$, delivering a sustained throughput of $> 5,000\text{ events/sec}$. Furthermore, our 10-minute sliding deduplication window prevents database starvation by collapsing repeated alerts from the same source IP into a single active ticket.

### Q29: How do you prevent a compromised honeypot from attacking internal corporate hosts?
* **Answer:** We enforce the Ingress-Only Virtual Isolation Invariant. Decoys operate in isolated subnets where outbound traffic to private RFC 1918 subnets is blocked at the virtual switch / hypervisor firewall layer. The only permitted outbound connection is the forwarder agent's authenticated HTTP channel to the SnareSight ingestion port.

### Q30: Why did you choose Server-Sent Events (SSE) over WebSockets?
* **Answer:** WebSockets are bi-directional and stateful, introducing connection management overhead and proxy renegotiation issues. In a SOC dashboard, telemetry data flows strictly in one direction: from the backend server to the analyst's browser. Server-Sent Events run over standard HTTP/1.1 or HTTP/2, handle automatic reconnections natively in browser APIs, pass effortlessly through corporate enterprise proxies, and require zero stateful ping-pong handshakes.

