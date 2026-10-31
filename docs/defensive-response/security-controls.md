# Security Controls & Defensive Safety Boundaries

## 1. Strict Defensive Scope Boundaries

SnareSight is exclusively a **Deception-Driven Threat Detection and Security Operations Platform**. In adherence to organizational safety policies, international legal norms, and project directives, the Defensive Response subsystem enforces strict prohibitions against offensive or unsafe operations:

| Capability | Policy Status | Enforcement Mechanism |
| :--- | :--- | :--- |
| **Honeypot Decoy Canary Rotation** | **PERMITTED** | Internal database state mutation and sensor configuration reload. |
| **Deception Sensitivity Boosting** | **PERMITTED** | Dynamic threshold adjustment within SnareSight detection engine. |
| **Honeypot Session Sandbox Isolation** | **PERMITTED** | Virtual route modification strictly inside honeypot container cluster. |
| **Full Telemetry Sample Rate Boost** | **PERMITTED** | Adjusts sensor logging verbosity to capture forensic detail. |
| **Evidence Retention Holds** | **PERMITTED** | Flags internal database records with SHA-256 integrity metadata. |
| **Offensive Hacking / Counter-Attacks** | **STRICTLY PROHIBITED** | Disallowed by architecture; no exploit payloads or network attack tools exist. |
| **Arbitrary OS Shell Execution** | **STRICTLY PROHIBITED** | No shell or process spawning APIs (`os.system`, `subprocess`) exist in response service. |
| **External Firewall / Network IP Blocking** | **STRICTLY PROHIBITED** | SnareSight does not execute iptables, cloud security group edits, or upstream routing changes. |
| **Autonomous Action Execution** | **STRICTLY PROHIBITED** | Explicit human approval gate required for all impactful mitigation steps. |

---

## 2. Authentication & Role-Based Access Control (RBAC)

All `/api/v1/response/*` endpoints enforce authentication via JWT bearer tokens and verify analyst roles:

```python
# RBAC Enforcement Matrix
READ_ACCESS      = ["viewer", "operator", "analyst", "admin"]
ANALYST_ACCESS   = ["analyst", "admin"]
ADMIN_ACCESS     = ["admin"]
```

- **Viewing cases, metrics, playbooks, recommendations:** Available to all authenticated roles.
- **Creating cases, adding notes, linking entities, running recommendation engine, executing playbooks:** Requires `analyst` or `admin`.
- **Authorizing dual-custody approval requests:** Requires `admin` (or designated senior reviewer distinct from requester).
- **Executing application containment actions:** Restricted to authorized execution handlers after approval verification.

---

## 3. Separation of Duties Enforcement

To prevent rogue or unilateral actions by an analyst, self-approval is blocked at the service level:

```python
if approval.requested_by == user.username:
    raise HTTPException(
        status_code=403,
        detail="Separation of duties violation: Requester cannot approve their own action request."
    )
```

---

## 4. Input Sanitization & Idempotency

- **Pydantic Validation:** All request payloads are validated through strongly-typed Pydantic schemas (`schemas.py`), stripping unexpected keys and preventing injection.
- **UUID Validation:** Identifiers are strictly validated against standard UUID formats to prevent SQLite/PostgreSQL conversion errors or SQL injection.
- **Idempotent Action Execution:** Every action record checks for duplicate execution runs to prevent double-rotation or conflicting session routing.

