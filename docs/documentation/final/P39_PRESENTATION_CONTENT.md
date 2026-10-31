# Academic Project Presentation Package: Slide Outline & Speaker Notes

**Document Version:** 1.0.0  
**Phase:** 8 — Testing, Demonstration & Project Handover  
**Document:** `docs/final/P39_PRESENTATION_CONTENT.md`  
**Target Duration:** 15–20 Minutes (15 Structured Slides)  

---

### SLIDE 1: Title & Project Identity
* **Slide Title:** SnareSight: Deception-Driven Threat Detection & Security Operations Platform
* **Subtitle:** An Evidence-Based Architecture for High-Fidelity Cyber Defense
* **Key Bullets:**
  * Project Domain: Applied Cybersecurity, Threat Intelligence & SOC Operations.
  * Architectural Core: Isolated Deception Decoys $\to$ Deterministic Threat Detection $\to$ Graph Correlation $\to$ MITRE ATT&CK Mapping.
  * Deliverable: Browser-Based Full-Stack Web Application (React 18 + FastAPI + PostgreSQL 16).
* **Suggested Visual:** Project logo, architecture banner, and verified release status badge (`v1.0.0 Release Candidate`).
* **Speaker Notes:** *"Good morning, respected mentors and evaluators. Today, we present SnareSight, a browser-based cyber deception and threat detection platform. Modern SOCs are inundated with ambiguous alerts from perimeter firewalls. SnareSight introduces an asymmetric advantage: by deploying isolated decoy assets with zero legitimate business traffic, any observed interaction is unauthorized by definition. Over the next 15 minutes, we will walk you through the problem, our architecture, technical feasibility, and live demonstration."*
* **Evidence Link:** [README.md](file:///c:/Projects/SnareSight/README.md)
* **Likely Reviewer Question:** *"Is this a native desktop app or a web application?"*  
  * *Answer:* *"SnareSight is strictly a browser-based web application with a React 18 TypeScript frontend and a FastAPI backend."*

---

### SLIDE 2: The Core Problem Statement
* **Slide Title:** The Perimeter Dilemma & Alert Fatigue
* **Key Bullets:**
  * Perimeter defenses inspect $>99.9\%$ legitimate business traffic $\to$ severe signal-to-noise deficit.
  * Enterprise SOC analysts face thousands of ambiguous alerts daily $\to$ burnout and high false-positive rates.
  * Adversaries easily bypass signature filters using encrypted channels and living-off-the-land techniques.
  * Once inside the network perimeter, intruder dwell time averages weeks or months before detection.
* **Suggested Visual:** Split diagram: Perimeter Noise (thousands of red/green packets) vs Deception Clarity (100% signal).
* **Speaker Notes:** *"The fundamental flaw in traditional network defense is that perimeter tools must inspect everything to catch rare attacks. In contrast, deception technology operates on an immutable principle: legitimate users have no business touching a decoy. Therefore, every hit is an actionable signal."*
* **Evidence Link:** [01_PROBLEM_UNDERSTANDING.md](file:///c:/Projects/SnareSight/docs/final/01_PROBLEM_UNDERSTANDING.md)
* **Likely Reviewer Question:** *"Why not just tune existing SIEM correlation rules?"*  
  * *Answer:* *"Tuning SIEM rules on perimeter logs is an endless game of whack-a-mole because business traffic constantly changes. Deception eliminates the baseline ambiguity entirely."*

---

### SLIDE 3: Motivation & The Deception Advantage
* **Slide Title:** Why Cyber Deception? The Asymmetric Advantage
* **Key Bullets:**
  * **Zero Legitimate Traffic Baseline:** Decoys have no authentic accounts or business utility.
  * **Safe Observability:** Observe attacker tradecraft, tooling, and lateral movement safely in an isolated sandbox.
  * **Early Warning Indicator:** Catches adversaries during initial reconnaissance before they touch production databases.
  * **Explainable Detection:** Replaces opaque black-box machine learning with deterministic, auditable rules.
* **Suggested Visual:** Concentric defensive rings showing Decoy Sensors acting as an early tripwire.
* **Speaker Notes:** *"Deception forces attackers to be right 100% of the time. If an attacker scans a subnet and probes 10 servers, touching even one decoy immediately trips the alarm and exposes their tools and IP coordinates."*
* **Evidence Link:** [HONEYPOT_OPERATIONS_MANUAL.md](file:///c:/Projects/SnareSight/docs/documentation/HONEYPOT_OPERATIONS_MANUAL.md)

---

### SLIDE 4: Project Objectives & Operational Boundaries
* **Slide Title:** Project Objectives & Explicit Scope Boundaries
* **Key Bullets:**
  * **Primary Objectives:** Ingest telemetry $\to$ Normalize $\to$ Detect $\to$ Score $\to$ Correlate into Attack Chains $\to$ Map to MITRE ATT&CK $\to$ Enable Analyst Containment.
  * **Strict Scope Boundaries:**
    * **NOT a SIEM Replacement:** Focused on high-fidelity deception, not general syslog hoarding.
    * **NOT an Antivirus / EDR Tool:** Does not monitor endpoint desktop processes.
    * **Zero-Execution Invariant:** Malicious binaries are quarantined and hashed, never executed.
    * **Non-Attribution Discipline:** IP profiles cluster network behavior; they do not claim legal proof of human identity.
* **Suggested Visual:** Scope boundary diagram contrasting SnareSight vs Generic SIEM vs Malware Sandbox.
* **Speaker Notes:** *"To maintain engineering discipline, we established clear boundaries. SnareSight is purely defensive. Under our Zero-Execution rule, we never detonate malware on the server, and we never claim an IP address proves the physical identity of an individual."*
* **Evidence Link:** [SECURITY_AND_PRIVACY.md](file:///c:/Projects/SnareSight/docs/documentation/SECURITY_AND_PRIVACY.md)

---

### SLIDE 5: End-to-End Processing Workflow
* **Slide Title:** The 16-Stage Telemetry-to-Containment Pipeline
* **Key Bullets:**
  * 1. Decoy Interaction $\to$ 2. Ingestion Auth (`X-Sensor-Key`) $\to$ 3. Zero-Password Salted Redaction.
  * 4. Schema Normalization $\to$ 5. Rule Matching $\to$ 6. Dual-Metric Scoring (Severity vs Confidence).
  * 7. MITRE Evidence Mapping $\to$ 8. Temporal Session Correlation $\to$ 9. Attack Chain Graphing.
  * 10. Threat Actor Profiling $\to$ 11. Triage Queue (SSE) $\to$ 12. Case Containment (iptables/UFW).
* **Suggested Visual:** Flowchart detailing the data movement through the 16 stages.
* **Speaker Notes:** *"Here is the complete journey of an intrusion. An adversary interacts with an emulated decoy. Telemetry is authenticated, stripped of plaintext passwords, normalized, evaluated against 10 rules, scored independently for severity and confidence, clustered into sessions, and pushed live to the analyst dashboard."*
* **Evidence Link:** [02_PROPOSED_APPROACH.md](file:///c:/Projects/SnareSight/docs/final/02_PROPOSED_APPROACH.md)

---

### SLIDE 6: System Component Architecture
* **Slide Title:** Modular Monolith Architecture
* **Key Bullets:**
  * **Single Deployable Process:** FastAPI backend structuring 15 decoupled domain modules.
  * **Authoritative Store:** PostgreSQL 16 with SQLAlchemy 2.0 ORM and Alembic migrations.
  * **Reactive Push:** Server-Sent Events (SSE) broadcasting notifications directly over HTTP.
  * **Single Page Application:** React 18, TypeScript, Tailwind CSS, Recharts, and React Flow.
* **Suggested Visual:** Full C4 / Mermaid System Architecture Diagram.
* **Speaker Notes:** *"We selected a Modular Monolith architecture. By avoiding microservices, we eliminated network serialization overhead, distributed transactions, and multi-container complexity while maintaining strict domain separation."*
* **Evidence Link:** [SYSTEM_ARCHITECTURE.md](file:///c:/Projects/SnareSight/docs/documentation/SYSTEM_ARCHITECTURE.md)

---

### SLIDE 7: Technology Stack & Selection Rationale
* **Slide Title:** Technology Stack & Engineering Rationale
* **Key Bullets:**
  * **Frontend:** React 18 + Vite (fast HMR, React Flow graph rendering, strict TypeScript).
  * **Backend:** Python 3.11+ + FastAPI (asynchronous ASGI, automatic OpenAPI docs, Pydantic type safety).
  * **Persistence:** PostgreSQL 16 + Alembic (ACID transactions, JSONB metadata, audit immutability).
  * **Push:** Server-Sent Events (lightweight unidirectional streaming, zero WebSocket state overhead).
  * **Packaging:** Docker Compose multi-stage containers with non-root user execution.
* **Suggested Visual:** Technology stack matrix comparing chosen tools against rejected alternatives.
* **Speaker Notes:** *"Every technology choice was deliberate. FastAPI provides asynchronous throughput and type contracts; PostgreSQL provides relational integrity and JSON flexibility; and SSE provides real-time streaming without WebSocket overhead."*
* **Evidence Link:** [03_TECHNICAL_FEASIBILITY.md](file:///c:/Projects/SnareSight/docs/final/03_TECHNICAL_FEASIBILITY.md)

---

### SLIDE 8: Threat Detection & Dual-Metric Scoring
* **Slide Title:** Explainable Threat Detection & Dual Scoring
* **Key Bullets:**
  * **10 Catalogue Detection Rules:** Covering brute force (`AUTH-001`), traversal (`WEB-002`), scans (`WEB-001`).
  * **Decoupled Scoring Policy:**
    * **Severity (0–100):** Asset impact assessment (target decoy bonus, multi-vector penalty).
    * **Confidence (0–100):** Evidentiary proof (baseline fidelity, repetition count, signature precision).
  * **Deduplication:** 10-minute suppression window prevents alert floods during automated scanner sweeps.
* **Suggested Visual:** Dual-metric scatter plot: High Severity / High Confidence vs Low Severity / High Confidence.
* **Speaker Notes:** *"Most systems use a single severity number. We decouple Severity from Confidence. A port scan has 95% Confidence but only 30% Severity. A successful decoy login has 85% Severity and 95% Confidence. This distinction completely prevents alert fatigue."*
* **Evidence Link:** [DETECTION_AND_ATTACK_MAPPING.md](file:///c:/Projects/SnareSight/docs/documentation/DETECTION_AND_ATTACK_MAPPING.md)

---

### SLIDE 9: Evidence-Grounded MITRE ATT&CK Integration
* **Slide Title:** Strict Evidence-Grounded ATT&CK Mapping
* **Key Bullets:**
  * **Zero Speculative Attribution:** Techniques are mapped only when supported by concrete event records.
  * **Enterprise Matrix Heatmap:** Dynamic color intensity reflecting observed tradecraft frequency.
  * **Technique Drill-Down:** Inspect formal MITRE description, mapped detection rules, and raw forensic events.
  * **Analyst Verification Gate:** Human-in-the-loop review interface to verify or dispute mappings.
* **Suggested Visual:** Screenshot of interactive MITRE ATT&CK Matrix heatmap from `/mitre`.
* **Speaker Notes:** *"In SnareSight, MITRE mapping is not a theoretical marketing feature. Clicking any illuminated technique opens a panel linking the exact raw HTTP requests and timestamps that proved the technique occurred."*
* **Evidence Link:** [frontend/src/features/mitre/](file:///c:/Projects/SnareSight/frontend/src/features/mitre/)

---

### SLIDE 10: Multi-Stage Correlation & Attack-Chain DAG
* **Slide Title:** Session Correlation & Interactive Attack Chains
* **Key Bullets:**
  * **Session Clustering:** Groups events by `(Source IP, Sensor ID, 10-Minute Window)`.
  * **Attack Chain Reconstruction:** Automatically stitches isolated events into a connected intrusion narrative.
  * **Interactive Graph (React Flow):** Visualizes stage progression: Recon $\to$ Discovery $\to$ Credential Access.
  * **Node Exploration:** Click any stage node to view supporting forensic payloads and timing deltas.
* **Suggested Visual:** Screenshot of the interactive React Flow DAG canvas from `/attack-chains`.
* **Speaker Notes:** *"Instead of forcing analysts to read 50 disconnected log rows, SnareSight constructs an interactive graph. The analyst sees the attacker's step-by-step journey across tactics in chronological sequence."*
* **Evidence Link:** [frontend/src/pages/AttackChains/](file:///c:/Projects/SnareSight/frontend/src/pages/AttackChains/)

---

### SLIDE 11: SOC Dashboard & Analyst Workspace
* **Slide Title:** SOC Operations Dashboard & Response Workspace
* **Key Bullets:**
  * **Real-Time Overview:** Executive KPIs, MTTD tracking ($< 100\text{ ms}$), decoy health status grid.
  * **Alert Triage Center:** Status transitions (`NEW` $\to$ `TRIAGED` $\to$ `INVESTIGATING` $\to$ `RESOLVED`).
  * **Defensive Containment:** Automated generation of copy-pasteable firewall blocking scripts (`iptables`, `UFW`).
  * **Compliance Retention Holds:** Prevents automated data pruning on legally sensitive incident evidence.
* **Suggested Visual:** Composite screenshot showing Overview Dashboard, Alert Drawer, and Containment Modal.
* **Speaker Notes:** *"The SOC Dashboard is built for real-world analyst velocity. An analyst claims an alert, opens an incident case, reviews the attack chain, and clicks one button to generate a perimeter iptables blocking script."*
* **Evidence Link:** [SOC_ANALYST_USER_MANUAL.md](file:///c:/Projects/SnareSight/docs/documentation/SOC_ANALYST_USER_MANUAL.md)

---

### SLIDE 12: Live Demonstration & Evaluation Harness
* **Slide Title:** The Self-Contained Demonstration Lab (`/demo`)
* **Key Bullets:**
  * **6 Deterministic Attack Scenarios:** Web Brute Force (SCN-A), Credential Stuffing (SCN-B), Traversal (SCN-C), etc.
  * **Zero External Dependencies:** Executes deterministically in offline lab environments.
  * **Automated Quality Evaluator:** Measures Detection Precision ($100\%$), Recall ($100\%$), and F1-Score ($1.000$).
  * **Selective Cleanup:** Purges temporary demonstration data while preserving cases with Retention Holds.
* **Suggested Visual:** Screenshot of `/demo` interface showing scenario trigger cards and evaluation matrix.
* **Speaker Notes:** *"To make evaluation seamless and reproducible, we built the Demonstration Lab directly into the application. In a moment, we will trigger Scenario A and observe the complete detection, correlation, and response cycle live."*
* **Evidence Link:** [LIVE_DEMONSTRATION_VALIDATION.md](file:///c:/Projects/SnareSight/docs/final/LIVE_DEMONSTRATION_VALIDATION.md)

---

### SLIDE 13: Technical Feasibility & Testing Verification
* **Slide Title:** Empirical Verification & Quality Assurance
* **Key Bullets:**
  * **Backend Pytest Suite:** **532 / 532 tests passing (100%)** across 15 modular subsystems.
  * **Frontend Vitest Suite:** **9 / 9 tests passing (100%)** covering UI contracts and state.
  * **Production Bundling:** Vite transforms **1618 modules in 3.04s** with 0 TypeScript errors.
  * **Operational Resilience:** internal health probes (`/live`, `/ready`), automated database backups with SHA-256 checksums, and dry-run isolated restore validation.
* **Suggested Visual:** Terminal output snippets showing 532 passed tests and clean Docker Compose status.
* **Speaker Notes:** *"Our claims are supported by concrete empirical evidence. 532 backend tests and 9 frontend tests pass with a 100% success rate. The database schema has a verified 9-revision migration history, and every backup undergoes automated dry-run restore validation."*
* **Evidence Link:** [TESTING_AND_QA_GUIDE.md](file:///c:/Projects/SnareSight/docs/documentation/TESTING_AND_QA_GUIDE.md)

---

### SLIDE 14: Honest Progress Report & Known Limitations
* **Slide Title:** Current Implementation Status & Known Constraints
* **Key Bullets:**
  * **Fully Implemented & Verified:** Ingestion, Redaction, 10 Rules, Scoring, Correlation, ATT&CK, DAG, Cases, Backups, Demo.
  * **Honest Limitations:**
    * Rules `CMD-001` and `FILE-001` deferred pending physical shell honeypot hardware deployment.
    * Single frontend JS chunk is 659 kB (code-splitting recommended).
    * IP threat profiles cluster network telemetry, not verified physical human identities.
* **Suggested Visual:** Progress matrix table highlighting verified status across all 15 modules.
* **Speaker Notes:** *"In academic research, intellectual honesty is paramount. We clearly distinguish between what is verified and what is deferred. Our web decoy, ingestion pipeline, scoring, and correlation are complete and verified; shell execution rules are deliberately deferred until hardware deployment."*
* **Evidence Link:** [05_CURRENT_PROGRESS.md](file:///c:/Projects/SnareSight/docs/final/05_CURRENT_PROGRESS.md)

---

### SLIDE 15: Conclusion & Future Roadmap
* **Slide Title:** Conclusion & Future Research Directions
* **Key Bullets:**
  * **Summary:** SnareSight successfully proves the viability of high-fidelity cyber deception as an antidote to alert fatigue.
  * **Future Roadmap:**
    * Distributed forwarder agents with mutual TLS (mTLS).
    * STIX 2.1 / TAXII automated threat intelligence feed export.
    * Automated API push to cloud firewalls (AWS WAF, Cloudflare).
    * Expansion to SMB, Redis, and Kubernetes decoys.
* **Suggested Visual:** Roadmap timeline showing Phase 9 & Phase 10 extension milestones.
* **Speaker Notes:** *"In conclusion, SnareSight transforms deceptive interaction into actionable, explainable intelligence. We thank our mentors for their guidance, and we invite your questions and technical inspection."*
* **Evidence Link:** [PROJECT_HANDOVER.md](file:///c:/Projects/SnareSight/docs/documentation/PROJECT_HANDOVER.md)

