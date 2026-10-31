# SnareSight: MVP & Phased Extension Boundaries
**Document ID:** ARCH-012  
**Status:** Approved Project Phasing Scope  

---

## 1. Scope Discipline & Principles

To guarantee that SnareSight remains a high-quality, production-grade cybersecurity platform without succumbing to feature creep, development is strictly partitioned into three distinct implementation tiers.

---

## 2. Implementation Tiers

### Level 1: Core Minimum Viable Product (MVP) — Immediate Focus
* **Decoy:** One isolated web-login honeypot (simulating an administrative corporate login portal).
* **Ingestion:** Authenticated REST ingestion endpoint (`/api/v1/ingest/events`) with schema validation and provenance tagging.
* **Database:** PostgreSQL schema with Alembic migrations for events, sessions, alerts, and attack chains.
* **Detection:** Deterministic rule engine covering:
  * Repeated authentication failures (brute-force burst).
  * Honeypot authentication success (immediate high-priority alert).
  * Suspicious URL path enumeration (`/admin`, `/wp-admin`, `/.env`, `/.git`).
* **Correlation:** Temporal window and session-based correlation linking related events into linear attack progressions.
* **Intelligence:** Static catalog of MITRE ATT&CK techniques with evidence-backed association.
* **Dashboard:** Complete React + Vite + Tailwind interface:
  * Executive Overview with KPI metric cards.
  * Live Event Feed powered by Server-Sent Events (SSE).
  * Alert Triage Center.
  * Interactive Attack-Chain Visualizer powered by React Flow.
  * Interactive MITRE ATT&CK Matrix Explorer.
* **Testing:** Pytest backend tests and reproducible simulation attack scripts.

### Level 2: High-Value Enhancements (Post-MVP Core)
* **Decoy Expansion:** Modular Cowrie SSH honeypot adapter for command and terminal session capture.
* **Investigations:** Case management workspace with analyst notes, audit trails, and defensive recommendations.
* **Reporting:** Automated PDF and JSON forensic incident report exports with IOC extraction.
* **Health:** Automated decoy heartbeat monitoring and pipeline backpressure telemetry.

### Level 3: Optional Future Extensions (Candidate Post-MVP)
* **Statistical Anomaly Detection:** Baseline traffic frequency analysis.
* **Decoy Diversity:** SMB, FTP, or Telnet specialized deception decoys.
* **External Threat Intel:** Enriching observed IP addresses with reputation scoring (AbuseIPDB, VirusTotal).

---

## 3. Strict Boundary Rules

1. **No Level 2 or 3 Feature may delay Level 1 MVP:** Work on Cowrie SSH, PDF export, or external intelligence will not commence until Level 1 MVP features are fully implemented, tested, and verified.
2. **Deception-First Rule:** Every feature must directly derive from honeypot telemetry and analyst response workflows.

