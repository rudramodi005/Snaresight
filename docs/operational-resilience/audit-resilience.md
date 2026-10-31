# Immutable Audit Trail & Cryptographic Hash Chain Integrity

## 1. Regulatory Requirements & Immutability

SOC compliance (SOC 2 Type II, ISO 27001, NIST SP 800-53) mandates that security operational actions, access control decisions, backup generations, and defensive mitigations must be immutably recorded.

In SnareSight:
- Users (including administrators) are strictly barred from modifying or deleting audit records.
- All sensitive tokens, passwords, and API keys are automatically redacted prior to persistence.

---

## 2. Cryptographic Hash Chain Architecture

To detect database administrator tampering or malicious table truncation:
- Each audit log entry is bound into a SHA-256 cryptographic hash sequence:
  $$\text{Hash}_i = \text{SHA256}(\text{Hash}_{i-1} \parallel \text{id}_i \parallel \text{timestamp}_i \parallel \text{actor}_i \parallel \text{action}_i \parallel \text{resource\_id}_i)$$
- The endpoint `POST /api/v1/resilience/audit/verify` traverses the audit log in chronological order, recomputes the expected hash chain, and identifies any broken links, modified payloads, or deleted records.
- Any integrity failure triggers `RULE-INT-AUDIT-05` (Audit Trail Integrity Anomaly or Persistence Failure).

