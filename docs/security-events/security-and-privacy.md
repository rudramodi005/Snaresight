# Security, Privacy & Integrity Guardrails

## 1. Zero Credential Persistence & Leakage Invariant
Authentication payloads collected by decoys frequently include usernames and passwords. While usernames are indexed for brute-force analytics, **passwords and credentials must never be stored or exposed**.

- **Dynamic Payload Scrubbing:**
  Before returning `normalized_payload` or `provenance`, the `SecurityEventsService` runs `_scrub_sensitive_dict`.
- **Target Patterns:**
  Keys matching `password`, `pass`, `secret`, `token`, `key`, `auth`, `authorization`, `credential`, `pwd`, or `private` are redacted to `"[REDACTED_CREDENTIAL]"`.

---

## 2. Inbound Passive Deception Only
- **Zero Outbound Reconnaissance:** The system operates strictly as a passive listener on decoy sockets. No outbound ping sweeps, port scans, or banner grabs are executed against observed IPs.
- **No Deanonymization Attacks:** The platform does not attempt to breach or deanonymize proxies or VPN infrastructure.

---

## 3. Strict Non-Attribution Policy
- **No Attacker Identity Claims:** Under no circumstances does the platform assert physical human identity or nation-state attribution (e.g. "APT29", "Lazarus") based on honeypot telemetry.
- **Routing vs Actor Realities:** Network artifacts (IPs, User-Agents) are frequently shared across botnets, commercial VPNs, and consumer CG-NAT. Telemetry is designated strictly as **"Observed Inbound Artifacts"**.

---

## 4. Role-Based Access Control (RBAC)
- `viewer`: Read-only access to event lists, summaries, and timelines.
- `analyst`: Ability to attach notes, update review status (`UNDER_REVIEW`, `REVIEWED`, `ESCALATED`, `DISMISSED`), and run comparisons.
- `admin` / `investigator`: Full access, including linking events to investigation clusters.

---

## 5. Non-Repudiation & Audit Immutability
All status changes, analyst notes, and investigation associations are recorded in `event_audit_logs`. Audit entries are append-only; update and delete operations are prohibited.

