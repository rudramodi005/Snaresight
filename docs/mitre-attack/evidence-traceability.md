# Evidence-Based Traceability & Audit Ladder

## The Traceability Chain
SnareSight enforces full bidirectionality across its security objects:
```
Technique (T1110)
    │
    ▼
Mapping Definition (v1.0 Registry)
    │
    ▼
Detection Rule (AUTH-001: SSH Brute Force)
    │
    ▼
Supporting Alert (ALT-2026-...)
    │
    ▼
Observed Telemetry Event (EVT-...)
    │
    ▼
Session / Investigation (SES-... / CMP-...)
```

## Traceability API
The `/api/v1/attack/traceability` endpoint aggregates all active mappings with supporting alert details:
- If a live alert exists, the endpoint attaches the alert ID, title, severity, session ID, and event ID.
- The `navigation_url` property provides direct routing links:
  - `/alerts?alert_id=<id>`
  - `/events?event_id=<id>`
  - `/sessions?session_id=<id>`
- If no live alert has occurred yet, the entry remains traceable to the configured rule definition with a link to inspect the technique in `/mitre?technique_id=<id>`.

## Analyst Inspection Workflow
When viewing any technique in the Technique Detail Drawer, analysts can:
1. Review all associated detection rules and rationale.
2. Inspect individual live alerts with timestamps and evidence summaries.
3. Jump directly into the Alert Triage Center or Session Investigation Page with a single click.

