# Approval Workflow & Separation of Duties

## 1. Overview & Regulatory Rationale

In high-consequence security operations, automated or unilateral containment actions pose significant risk of denial of service, false accusation, or investigative disruption. SnareSight enforces a rigorous **Separation of Duties** and **Dual-Custody Approval Gate** mechanism (`backend/app/modules/response/service.py`).

No controlled defensive action can be executed without an explicitly approved `ResponseApproval` request.

---

## 2. Separation of Duties Policy

1. **Role-Based Authorization:**
   - Any SOC analyst with role `operator`, `analyst`, or `admin` can **request** an action.
   - Only users with role `admin` or an independent senior analyst designated by policy can **approve** or **reject** an action.
2. **Self-Approval Prohibition:**
   - The user who creates an approval request (`requested_by`) cannot approve their own request (`approved_by`).
   - If a user attempts to approve their own request, the system raises `403 Forbidden` (`Requester cannot approve their own action request`).
3. **Mandatory Operational Justification:**
   - Every approval request requires a clear explanation of operational necessity (`justification`).
   - Every decision (approval or rejection) requires an explicit reason (`decision_reason`).

---

## 3. Dual-Custody Approval Lifecycle

```mermaid
sequenceDiagram
    autonumber
    actor Requester as Requesting Analyst
    actor Approver as Reviewing Lead / Admin
    participant Service as ResponseService
    participant DB as Database
    participant Audit as SystemAuditLog

    Requester->>Service: POST /cases/{id}/approvals (action_type, justification)
    Service->>DB: Create ResponseApproval (status=PENDING, requested_by=Requester)
    Service->>DB: Transition Case to AWAITING_APPROVAL
    Service->>Audit: Log APPROVAL_REQUESTED
    Service-->>Requester: Approval Request Created

    Approver->>Service: POST /cases/{id}/approvals/{approval_id}/decision (decision=APPROVE, reason)
    alt Requester == Approver
        Service-->>Approver: 403 Forbidden (Self-approval disallowed)
    else Requester != Approver
        Service->>DB: Update ResponseApproval (status=APPROVED, approved_by=Approver)
        Service->>DB: Transition Case to APPROVED
        Service->>Audit: Log APPROVAL_GRANTED
        Service-->>Approver: Approval Confirmed
    end
```

---

## 4. Controlled Action Catalog

The approval gate guards the following safe application actions:

| Action Identifier | Description | Reversible |
| :--- | :--- | :--- |
| `HONEYPOT_SENSITIVITY_BOOST` | Elevates detection sensitivity, lowering alert thresholds on specified decoy sensors. | Yes |
| `CREDENTIAL_CANARY_ROTATION` | Deprecates observed canary credentials and issues fresh decoy tokens into honeypot forms. | Yes |
| `SESSION_ISOLATION` | Routes future connections from an attacker IP or fingerprint into an isolated sandbox environment. | Yes |
| `TELEMETRY_SAMPLE_RATE_MAX` | Increases logging detail from sampled mode to 100% full packet / event capture. | Yes |

---

## 5. Pre-Execution Validation Checks

Before an approved action is executed by the system:
1. **Approval State Verification:** The associated approval ID must be in `APPROVED` status.
2. **Idempotency Guard:** The system verifies that the action has not already been executed for this case.
3. **Parameter Boundary Check:** Action parameters are validated to ensure only approved honeypot resources are targeted.

