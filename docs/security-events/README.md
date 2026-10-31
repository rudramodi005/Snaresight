# SnareSight Security Events Explorer Subsystem

## Overview
The **Security Events Explorer Subsystem** (Task P27 / Prompt 27 of 40, Phase 6: Security Operations Center Dashboard) provides an advanced, evidence-backed workspace for authorized SOC analysts to search, filter, forensic-inspect, compare, and investigate normalized honeypot events.

Rather than presenting disjointed raw logs or static mockups, the explorer links each normalized event to its underlying raw capture, correlated activity session, observed source profile, threat detection rules, security alerts, behavioral sequences, investigation clusters, and MITRE ATT&CK techniques.

---

## Core Invariants & Guardrails

1. **Zero Credential Persistence & Leakage Invariant:**
   - Raw credentials, passwords, passphrases, and private tokens submitted to honeypots are strictly scrubbed and replaced with redaction tokens (`"[REDACTED_CREDENTIAL]"`) before display in the explorer or transmission across APIs.
2. **Strict Non-Attribution Policy:**
   - Similarities in observed network attributes (ports, User-Agents, IP blocks, tool signatures) do **NEVER** constitute proof of physical human identity or state-sponsored attacker attribution. The system designates events as **"Observed Inbound Artifacts"** and provides an explicit non-attribution caveat during multi-event comparison.
3. **Non-Destructive Investigation Actions:**
   - Analyst notes and review statuses are recorded in an append-only audit trail (`event_audit_logs`). Original event telemetry and raw captures remain immutable.
4. **Server-Side Scalability & Bounded Memory:**
   - Server-side multi-attribute filtering, pagination, and bounded result sets prevent unconstrained queries from exhausting database or browser memory.
5. **Passive Inbound Deception:**
   - Zero outbound scanning, no port probing, and no active reconnaissance against observed external sources.

---

## Subsystem Navigation & Documentation

- [Architecture](architecture.md): High-level system design, data flow, and subsystem interactions.
- [Search & Filtering](search-and-filters.md): Multi-attribute server-side queries, debounced search, and index utilization.
- [Event Detail Inspection](event-detail.md): 6-tab forensic drawer structure, safe payload viewing, and provenance.
- [Cross-Subsystem Relationships](relationships.md): Linking events to sessions, source profiles, alerts, sequences, clusters, and MITRE.
- [Chronological Timeline](timeline.md): Assembling microsecond-accurate session and temporal event timelines.
- [Evidence Provenance](evidence-provenance.md): Ingestion pipeline stages, deduplication fingerprints, and integrity guarantees.
- [REST API Reference](api-reference.md): Complete specifications for all `/api/v1/events` endpoints.
- [Security & Privacy](security-and-privacy.md): Credential scrubbing, RBAC, input sanitization, and audit immutability.
- [Testing & Verification](testing.md): Automated test suites, test cases, and verification results.

