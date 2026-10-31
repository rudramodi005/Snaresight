# Investigation Clustering Methodology

## Purpose
The `ClusteringEngine` (`backend/app/modules/campaign_intelligence/clustering_engine.py`) provides deterministic, idempotent, and explainable grouping of observed telemetry into cohesive investigation clusters.

---

## 1. Candidate Entity Discovery

The clustering process examines unassociated or updated entities across multiple telemetry streams:
- **Activity Sessions (`sessions`):** Individual honeypot interaction timelines.
- **Observed Source Profiles (`source_profiles`):** Multi-session persistent source context baselines.
- **Behavioral Sequences (`behavioral_sequences`):** Multi-session attack chains and progression models.
- **Security Alerts (`security_alerts`):** High-fidelity detection engine triggers.

---

## 2. Correlation Dimensions

The clustering engine aggregates entities across four primary analytical dimensions:

### A. Infrastructure & Addressing Correlation
- **Shared Source IP:** Matches exact inbound IP addresses across disparate sessions and services.
- **Shared Subnet / ASN:** Identifies correlated scanning originating from contiguous network blocks (e.g., specific cloud hosting providers or bulletproof hosting subnets).

### B. Honeypot Service & Port Targeting
- **Target Sensor Co-occurrence:** Probes targeting identical sets of honeypot ports (e.g., simultaneous probes on SSH 2222, Telnet 2323, and HTTP 8080).
- **Service-Specific Payload Affinity:** Coordinated attacks deploying specialized payloads against specific emulated services.

### C. Signature & Tooling Fingerprints
- **HTTP User-Agent Strings:** Identical rare or scanner-specific User-Agent headers (e.g., `Hello, world`, `masscan/1.0`, custom python urllib headers).
- **SSH Client Identifiers / Banner Signatures:** Exact match of client software versions and cipher suites.
- **Observed Username Patterns:** Repeated probing of non-standard usernames (e.g., `miner_admin`, `pi_user_test`).

### D. Temporal & Sequencing Correlation
- **Burst Synchronization:** Multiple distinct sources executing probes within a tight time delta (e.g., within 300 seconds of each other).
- **Shared MITRE Progression:** Behavioral sequences exhibiting identical MITRE ATT&CK tactic progression (e.g., Reconnaissance -> Initial Access -> Discovery).

---

## 3. Idempotency & Conflict Prevention

To prevent duplicate cluster generation:
1. **Cluster Anchor Resolution:** Before creating a new cluster, the engine checks if any candidate entity is already a member of an existing `ACTIVE` or `UNDER_REVIEW` cluster.
2. **Incremental Membership Addition:** If a matching cluster is found, new entities are appended to the existing cluster via `ClusterMembershipModel` with explicit association reasons.
3. **Evidence De-duplication:** Evidence artifacts (`cluster_evidence`) are matched on `(cluster_id, evidence_type, evidence_value)` to prevent duplicate evidence insertion.

