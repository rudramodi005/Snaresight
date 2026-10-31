# SnareSight MITRE ATT&CK Threat Intelligence and Mapping Architecture

## Overview
The SnareSight MITRE ATT&CK Threat Intelligence and Mapping subsystem provides security operations center (SOC) analysts with an enterprise-grade, evidence-grounded framework for understanding adversary behavior observed across honeypot sensors.

By mapping detection rules and high-confidence deception telemetry directly to the MITRE ATT&CK Enterprise Matrix (v14.1), SnareSight bridges raw honeypot alerts with standardized adversary tactics, techniques, and procedures (TTPs).

## Core Capabilities
1. **Canonical Enterprise Matrix (14 Tactics)**: Full progression from Reconnaissance (`TA0043`) to Impact (`TA0040`), rendered in canonical MITRE order.
2. **Visual Mapping States**: Real-time visual categorization distinguishing between:
   - `ALERT_EVIDENCE`: Techniques with live honeypot alert observations.
   - `RULE_MAPPED`: Techniques covered by configured detection scenarios without live alerts.
   - `REVIEW_REQUIRED`: Mappings requiring human analyst triage.
   - `UNMAPPED`: Active catalogue techniques without configured detection coverage.
3. **Evidence-Based Traceability**: End-to-end auditability connecting Technique → Mapping Definition → Detection Rule → Live Alert Evidence → Telemetry Event → Session/Investigation.
4. **Analyst Review Workflow**: Controlled lifecycle for approving, rejecting, or requesting more evidence for behavioral mappings, backed by immutable audit history tables.
5. **Coverage Analytics**: Continuous calculation of rule-level and evidence-level catalogue coverage across all 14 tactics.

## Directory Structure
- `docs/mitre-attack/architecture.md`: Architectural design, data flow, and database schema.
- `docs/mitre-attack/catalogue.md`: STIX 2.1 catalogue ingestion, versioning, and lifecycle management.
- `docs/mitre-attack/matrix.md`: Matrix layout, scrolling ergonomics, and cell state visualization.
- `docs/mitre-attack/mapping-methodology.md`: Deception-to-ATT&CK mapping criteria and confidence scoring.
- `docs/mitre-attack/evidence-traceability.md`: Multi-layer evidence ladder and navigation linkage.
- `docs/mitre-attack/coverage-metrics.md`: Calculation algorithms for rule and alert coverage.
- `docs/mitre-attack/review-workflow.md`: Human-in-the-loop triage lifecycle and governance.
- `docs/mitre-attack/api-reference.md`: Complete OpenAPI endpoint specifications under `/api/v1/attack`.
- `docs/mitre-attack/security-and-testing.md`: Authorization controls, non-attribution compliance, and test suite verification.

