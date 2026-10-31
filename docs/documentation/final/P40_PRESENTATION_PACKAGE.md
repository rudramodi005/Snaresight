# SnareSight: Master Project Presentation Package (P40)

**Document Version:** 1.0.0  
**Phase:** 8 — Testing, Demonstration & Project Handover (Final Prompt 40/40)  
**Document:** `docs/final/P40_PRESENTATION_PACKAGE.md`  
**Classification:** Academic Review & Presentation Package  
**Date:** October 2026  

---

## 1. Presentation Overview & Evaluation Alignment

This package consolidates the complete presentation materials for the formal academic project evaluation and mentoring defense of **SnareSight: Deception-Driven Threat Detection & Security Operations Platform**.

The presentation is balanced equally across the five official evaluation criteria:
1. **Problem Understanding (20%):** Explaining the perimeter dilemma, alert fatigue, and the cyber deception advantage.
2. **Proposed Approach (20%):** The 16-stage pipeline from honeypot probe to perimeter firewall containment.
3. **Technical Feasibility (20%):** Empirical evidence of 541 passing tests, sub-100ms MTTD, and Docker Compose reproducibility.
4. **Innovation & Creativity (20%):** Decoupled dual-scoring, evidence-backed MITRE mapping, React Flow DAG, and dry-run restores.
5. **Current Progress (20%):** 15 verified subsystems, working demonstration lab, and honest disclosure of deferred shell rules.

---

## 2. Master Slide-by-Slide Content & Speaker Notes

### Slide 1: Title & Project Identity
* **Headline:** SnareSight: Deception-Driven Threat Detection & Security Operations Platform
* **Key Bullets:**
  * High-Fidelity Cyber Deception for Enterprise Virtual Lab Subnets.
  * Browser-Based Modular Monolith: React 18 + TypeScript + Vite | FastAPI + PostgreSQL 16.
  * Verified Release Candidate (`v1.0.0-RC`).
* **Speaker Notes:** *"Good morning, respected mentors and evaluators. Modern Security Operations Centers face an asymmetric crisis: perimeter firewalls generate thousands of ambiguous alerts daily. SnareSight introduces an asymmetric defensive advantage: by deploying isolated decoy assets with zero legitimate business traffic, any observed interaction is unauthorized by definition."*

### Slide 2: Problem Understanding — The Perimeter Dilemma
* **Headline:** Why Perimeter Defenses Fail: The Signal-to-Noise Deficit
* **Key Bullets:**
  * Perimeter firewalls and WAFs inspect $>99.9\%$ legitimate business traffic.
  * Rare attack signals are buried in overwhelming noise, leading to analyst alert fatigue and missed breaches.
  * Adversaries easily bypass perimeter filters using encrypted channels and living-off-the-land techniques.
  * Average intruder dwell time before detection frequently spans weeks or months.
* **Speaker Notes:** *"Perimeter tools must inspect everything to catch rare attacks. In contrast, deception technology operates on an immutable principle: legitimate users have no business touching a decoy. Therefore, every hit is an actionable signal."*

### Slide 3: Motivation — The Deception Advantage
* **Headline:** Cyber Deception: Turning Asymmetry Against the Adversary
* **Key Bullets:**
  * **Zero Legitimate Traffic Baseline:** Decoys have no authentic business utility.
  * **Safe Observability:** Observe attacker tradecraft, tooling, and lateral movement safely in an isolated sandbox.
  * **Early Warning Indicator:** Catches adversaries during initial reconnaissance before they touch production databases.
  * **Explainable Detection:** Replaces opaque black-box machine learning with deterministic, auditable rules.
* **Speaker Notes:** *"Deception forces attackers to be right 100% of the time. If an attacker scans a subnet and probes 10 servers, touching even one decoy immediately trips the alarm and exposes their tools and IP coordinates."*

### Slide 4: Objectives & Scope Boundaries
* **Headline:** Project Objectives & Explicit Scope Boundaries
* **Key Bullets:**
  * **Core Goals:** Ingest $\to$ Redact $\to$ Detect $\to$ Score $\to$ Correlate $\to$ Map to ATT&CK $\to$ Contain.
  * **Explicit Non-Goals (What SnareSight is NOT):**
    * NOT a general SIEM replacement (focused on deception).
    * NOT an Antivirus or EDR kernel agent.
    * Zero-Execution Rule: Quarantines payloads, never detonates malware.
    * Non-Attribution Discipline: IP profiles cluster network telemetry, not verified physical human identities.
* **Speaker Notes:** *"We established strict boundaries. SnareSight is purely defensive. Under our Zero-Execution rule, we never detonate malware on the server, and we never claim an IP address proves the physical identity of an individual."*

### Slide 5: Proposed Approach — 16-Stage Pipeline
* **Headline:** End-to-End Workflow: Telemetry to Perimeter Containment
* **Key Bullets:**
  * 1. Decoy Hit $\to$ 2. Token Ingestion (`X-Sensor-Key`) $\to$ 3. Salted SHA-256 Redaction.
  * 4. Pydantic Normalization $\to$ 5. PostgreSQL Storage $\to$ 6. 10 Catalogue Rules.
  * 7. Dual Scoring (Severity vs Confidence) $\to$ 8. MITRE Mapping $\to$ 9. Session Correlation.
  * 10. Attack Chain DAG $\to$ 11. SSE Live Push $\to$ 12. Case Containment (iptables).
* **Speaker Notes:** *"Here is the complete journey of an intrusion. An adversary interacts with an emulated decoy. Telemetry is authenticated, stripped of plaintext passwords, normalized, evaluated against 10 rules, scored independently for severity and confidence, clustered into sessions, and pushed live to the analyst dashboard."*

### Slide 6: System Component Architecture
* **Headline:** Modular Monolith Architecture
* **Key Bullets:**
  * **FastAPI Modular Core:** 15 decoupled domain routers under `/api/v1`.
  * **PostgreSQL 16 Relational Engine:** 42 normalized SQLAlchemy 2.0 models with 9-revision migration lineage.
  * **Reactive Push:** Server-Sent Events (SSE) broadcasting live alerts over HTTP without WebSockets overhead.
  * **React 18 Single-Page App:** TypeScript, Tailwind CSS, Recharts, and React Flow DAG visualizers.
* **Speaker Notes:** *"We selected a Modular Monolith architecture. By avoiding microservices, we eliminated network serialization overhead, distributed transactions, and multi-container complexity while maintaining strict domain separation."*

### Slide 7: Technology Stack & Selection Rationale
* **Headline:** Deliberate Technology Selection
* **Key Bullets:**
  * **Frontend:** React 18 + Vite (strict TypeScript, React Flow DAG rendering, sub-second HMR).
  * **Backend:** Python 3.11+ + FastAPI (asynchronous concurrency, native Pydantic schemas, automatic OpenAPI).
  * **Database:** PostgreSQL 16 + Alembic (ACID transactions, JSONB metadata, immutable audit trails).
  * **Streaming:** Server-Sent Events (lightweight unidirectional streaming, native browser reconnection).
  * **Packaging:** Docker Compose multi-stage containers with non-root security execution.
* **Speaker Notes:** *"Every technology choice was deliberate. FastAPI provides asynchronous throughput and type contracts; PostgreSQL provides relational integrity and JSON flexibility; and SSE provides real-time streaming without WebSocket overhead."*

### Slide 8: Threat Detection & Dual Scoring
* **Headline:** Explainable Detection & Dual-Metric Scoring
* **Key Bullets:**
  * **10 Catalogue Detection Rules:** Covering brute force (`AUTH-001`), traversal (`WEB-002`), scans (`WEB-001`).
  * **Decoupled Scoring Policy:**
    * **Severity (0–100):** Asset impact assessment (target decoy bonus, multi-vector penalty).
    * **Confidence (0–100):** Evidentiary proof (baseline fidelity, repetition count, signature precision).
  * **Deduplication:** 10-minute suppression window prevents alert floods during automated scanner sweeps.
* **Speaker Notes:** *"Most systems use a single severity number. We decouple Severity from Confidence. A port scan has 95% Confidence but only 30% Severity. A successful decoy login has 85% Severity and 95% Confidence. This distinction completely prevents alert fatigue."*

### Slide 9: Evidence-Grounded MITRE ATT&CK Mapping
* **Headline:** Strict Evidence-Grounded ATT&CK Mapping
* **Key Bullets:**
  * **Zero Speculative Attribution:** Techniques are mapped only when supported by concrete event records.
  * **Enterprise Matrix Heatmap:** Dynamic color intensity reflecting observed tradecraft frequency.
  * **Technique Drill-Down:** Inspect formal MITRE description, mapped detection rules, and raw forensic events.
  * **Analyst Verification Gate:** Human-in-the-loop review interface to verify or dispute mappings.
* **Speaker Notes:** *"In SnareSight, MITRE mapping is not a theoretical marketing feature. Clicking any illuminated technique opens a panel linking the exact raw HTTP requests and timestamps that proved the technique occurred."*

### Slide 10: Multi-Stage Correlation & Attack-Chain Graph
* **Headline:** Session Correlation & Interactive Attack Chains
* **Key Bullets:**
  * **Session Clustering:** Groups events by `(Source IP, Sensor ID, 10-Minute Window)`.
  * **Attack Chain Reconstruction:** Automatically stitches isolated events into a connected intrusion narrative.
  * **Interactive Graph (React Flow):** Visualizes stage progression: Recon $\to$ Discovery $\to$ Credential Access.
  * **Node Exploration:** Click any stage node to view supporting forensic payloads and timing deltas.
* **Speaker Notes:** *"Instead of forcing analysts to read 50 disconnected log rows, SnareSight constructs an interactive graph. The analyst sees the attacker's step-by-step journey across tactics in chronological sequence."*

### Slide 11: SOC Dashboard & Analyst Workspace
* **Headline:** SOC Operations Dashboard & Response Workspace
* **Key Bullets:**
  * **Real-Time Overview:** Executive KPIs, MTTD tracking ($< 100\text{ ms}$), decoy health status grid.
  * **Alert Triage Center:** Status transitions (`NEW` $\to$ `TRIAGED` $\to$ `INVESTIGATING` $\to$ `RESOLVED`).
  * **Defensive Containment:** Automated generation of copy-pasteable firewall blocking scripts (`iptables`, `UFW`).
  * **Compliance Retention Holds:** Prevents automated data pruning on legally sensitive incident evidence.
* **Speaker Notes:** *"The SOC Dashboard is built for real-world analyst velocity. An analyst claims an alert, opens an incident case, reviews the attack chain, and clicks one button to generate a perimeter iptables blocking script."*

### Slide 12: Live Demonstration & Evaluation Harness
* **Headline:** The Self-Contained Demonstration Lab (`/demo`)
* **Key Bullets:**
  * **6 Deterministic Attack Scenarios:** Web Brute Force (SCN-A), Credential Stuffing (SCN-B), Traversal (SCN-C), etc.
  * **Zero External Dependencies:** Executes deterministically in offline lab environments.
  * **Automated Quality Evaluator:** Measures Detection Precision ($100\%$), Recall ($100\%$), and F1-Score ($1.000$).
  * **Selective Cleanup:** Purges temporary demonstration data while preserving cases with Retention Holds.
* **Speaker Notes:** *"To make evaluation seamless and reproducible, we built the Demonstration Lab directly into the application. We can execute Scenario A and observe the complete detection, correlation, and response cycle live in under 6 minutes."*

### Slide 13: Technical Feasibility & Empirical Evidence
* **Headline:** Empirical Verification & Quality Assurance
* **Key Bullets:**
  * **Backend Pytest Suite:** **532 / 532 tests passing (100%)** across 15 modular subsystems.
  * **Frontend Vitest Suite:** **9 / 9 tests passing (100%)** covering UI contracts and state.
  * **Production Bundling:** Vite transforms **1618 modules in 3.04s** with 0 TypeScript errors.
  * **Operational Resilience:** Health probes (`/live`), backup snapshots with SHA-256 checksums, and dry-run isolated restore validation.
* **Speaker Notes:** *"Our claims are supported by concrete empirical evidence. 532 backend tests and 9 frontend tests pass with a 100% success rate. The database schema has a verified 9-revision migration history, and every backup undergoes automated dry-run restore validation."*

### Slide 14: Honest Progress Report & Known Limitations
* **Headline:** Current Implementation Status & Known Constraints
* **Key Bullets:**
  * **Fully Implemented & Verified:** Ingestion, Redaction, 10 Rules, Scoring, Correlation, ATT&CK, DAG, Cases, Backups, Demo.
  * **Honest Limitations:**
    * Rules `CMD-001` and `FILE-001` deferred pending physical shell honeypot hardware deployment.
    * Single frontend JS chunk is 659 kB (code-splitting recommended).
    * IP threat profiles cluster network telemetry, not verified physical human identities.
* **Speaker Notes:** *"In academic research, intellectual honesty is paramount. We clearly distinguish between what is verified and what is deferred. Our web decoy, ingestion pipeline, scoring, and correlation are complete and verified; shell execution rules are deliberately deferred until hardware deployment."*

### Slide 15: Conclusion & Future Scope
* **Headline:** Conclusion & Future Research Directions
* **Key Bullets:**
  * **Summary:** SnareSight successfully proves the viability of high-fidelity cyber deception as an antidote to alert fatigue.
  * **Future Roadmap:**
    * Distributed forwarder agents with mutual TLS (mTLS).
    * STIX 2.1 / TAXII automated threat intelligence feed export.
    * Automated API push to cloud firewalls (AWS WAF, Cloudflare).
    * Expansion to SMB, Redis, and Kubernetes decoys.
* **Speaker Notes:** *"In conclusion, SnareSight transforms deceptive interaction into actionable, explainable intelligence. We thank our mentors for their guidance, and we invite your questions and technical inspection."*

---

## 3. Associated Reviewer Deliverables

* **Timed Demo Script:** [docs/final/PRESENTATION_DEMONSTRATION_SCRIPT.md](file:///c:/Projects/SnareSight/docs/final/PRESENTATION_DEMONSTRATION_SCRIPT.md) (6m30s stage-by-stage presenter runbook).
* **Reviewer Q&A Defense:** [docs/final/LIKELY_REVIEWER_QUESTIONS.md](file:///c:/Projects/SnareSight/docs/final/LIKELY_REVIEWER_QUESTIONS.md) (30 rigorous technical questions & answers).
* **Reviewer Evidence Index:** [docs/final/EVIDENCE_INDEX.md](file:///c:/Projects/SnareSight/docs/final/EVIDENCE_INDEX.md) (Master index linking evidence files).
* **Evaluation Self-Assessment:** [docs/final/EVALUATION_SELF_ASSESSMENT.md](file:///c:/Projects/SnareSight/docs/final/EVALUATION_SELF_ASSESSMENT.md) (Objective 20-point rubric, Score: 93/100).
* **Readiness Checklist:** [docs/final/PRESENTATION_READINESS_CHECKLIST.md](file:///c:/Projects/SnareSight/docs/final/PRESENTATION_READINESS_CHECKLIST.md) (Day-of-presentation setup checklist).

