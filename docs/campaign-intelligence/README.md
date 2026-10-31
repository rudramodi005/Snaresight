# SnareSight Threat Campaign Intelligence & Investigation Grouping Subsystem

## Overview
The **Campaign Intelligence & Investigation Grouping Subsystem** (Task P24 / Prompt 24 of 40, Phase 5: Correlation & Activity Profiles) provides evidence-based aggregation of observed honeypot activities into structured, manageable **Investigation Clusters** (`investigation_clusters`).

Rather than leaving security analysts to examine isolated sessions, individual source profiles, or disparate detection alerts, this subsystem correlates multi-session patterns, behavioral sequences, and shared infrastructure indicators into cohesive investigation groups. It preserves strict evidentiary chains, supports analyst reviews, transparent relationship confidence scoring, and non-destructive cluster merges and splits.

---

## Core Objectives & Guardrails

1. **Strict Terminology & Non-Attribution Invariant:**
   - Groupings are strictly designated as **"Investigation Cluster"**, **"Related observed activity"**, **"Potential campaign cluster"**, **"Behavioral relationship"**, or **"Evidence-supported investigation group"**.
   - The platform **NEVER** claims confirmed threat actor attribution, physical human identity, or guaranteed attacker coordination. Overlapping infrastructure or tooling across internet-scale scans may stem from shared botnets, commercial cloud proxies, public scanning tools, or coincidentally similar automated probing.
2. **Transparent Relationship Confidence vs Detection Confidence:**
   - The system clearly distinguishes between **Event Severity** (impact of an event), **Detection Confidence** (certainty of a rule match), **Profile Priority** (analyst attention level), **Behavioral Sequence Severity** (progression risk), and **Cluster Relationship Confidence** (degree of evidence supporting the association between entities in the cluster).
3. **Non-Destructive Merge and Split Operations:**
   - When analysts merge clusters, original cluster records and audit trails remain preserved (`MERGED` status), pointing to the target cluster.
   - When splitting a cluster, selected entities are extracted into a new cluster with explicit provenance, while leaving the remaining entities intact.
4. **Idempotent Clustering Engine:**
   - The automated clustering engine evaluates candidate entities based on shared attributes (e.g., target honeypot ports, probe signatures, overlapping credentials, user agents) without generating duplicate clusters or duplicate evidence entries.
5. **Passive Inbound Deception:**
   - The system remains 100% passive and inbound. It conducts zero outbound probing, no active reconnaissance, and strictly maintains zero credential persistence.

---

## Subsystem Navigation & Documentation

- [Architecture](architecture.md): High-level system design, data flow, and subsystem interactions.
- [Data Model](data-model.md): Detailed schema for clusters, memberships, evidence, relationships, and audit logs.
- [Clustering Methodology](clustering-methodology.md): Rule-based, heuristics, and behavioral clustering algorithms.
- [Scoring Policy](scoring-policy.md): Relationship confidence formulas, signal weights, and contradiction penalties.
- [Lifecycle State Machine](lifecycle.md): State transitions from Candidate to Closed/Dismissed, validation, and analyst reviews.
- [Merge & Split Operations](merge-and-split.md): Non-destructive consolidation and separation procedures.
- [Investigation Timeline](investigation-timeline.md): Unified chronological ordering of correlated multi-source events.
- [API Reference](api-reference.md): Complete REST endpoint documentation and parameter specifications.
- [Security & Privacy](security-and-privacy.md): Credential scrubbing, access control, and privacy protections.
- [Testing & Verification](testing.md): Test suites, unit test coverage, and verification results.
- [P24 Existing Project Assessment](P24_EXISTING_PROJECT_ASSESSMENT.md): Pre-implementation repository audit.

