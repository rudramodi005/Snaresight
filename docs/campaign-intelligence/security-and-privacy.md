# Security, Privacy & Integrity Guardrails

## 1. Zero Credential Persistence Invariant
SnareSight honeypots collect raw connection and protocol interactions. However, passwords, passphrases, and secret tokens collected during brute force or credential stuffing attacks pose severe compliance and security risks.

- **Mandatory Scrubbing:** Passwords submitted during authentication attempts are replaced with cryptographic hashes or replaced with redaction tokens before insertion into `cluster_evidence` or `shared_indicators`.
- **Username Analytics Only:** Frequency analysis is performed exclusively on usernames (e.g. `root`, `admin`, `guest`) to identify scanning tools without ever storing entered passwords.

---

## 2. Inbound Passive Deception Only
- **Zero Outbound Scanning:** The Campaign Intelligence engine operates strictly on inbound telemetry received by honeypot listeners. It will never dispatch ping sweeps, port scans, DNS zone transfers, or banner grabs against suspect external IPs.
- **No Deanonymization Probing:** The system does not attempt to resolve TOR exit nodes, VPN providers, or proxies via active probing.

---

## 3. Strict Non-Attribution Policy
- **No Attacker Identity Claims:** Under no circumstances will the platform label an investigation cluster with physical human names, sovereign state organizations, or unverified APT monikers (e.g., "APT28", "Lazarus") without documented external intelligence ingestion.
- **Routing vs Actor Realities:** All indicators are documented as "Observed Inbound Artifacts". Because IP addresses are frequently spoofed, routed via compromised routers, or egressed through shared consumer CG-NAT, clusters are framed as **"Related observed activity"**.

---

## 4. Role-Based Access Control (RBAC)
Investigation management requires specific privileges:
- `viewer`: Read-only access to cluster lists, timelines, and topology graphs.
- `analyst`: Ability to triage clusters, change lifecycle states, add notes, attach evidence, and adjust priority.
- `admin` / `investigator`: Full permissions, including non-destructive merge and split operations.

---

## 5. Non-Repudiation & Audit Immutability
All status modifications, evidence attachments, merges, and splits are written directly to `cluster_audit_logs`. Audit entries are append-only; updates and deletions are prohibited at both the ORM and database trigger levels.

