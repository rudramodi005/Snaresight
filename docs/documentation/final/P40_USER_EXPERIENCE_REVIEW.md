# SnareSight: User Experience, Interface & Accessibility Review (P40)

**Document Version:** 1.0.0  
**Phase:** 8 — Testing, Demonstration & Project Handover (Final Prompt 40/40)  
**Document:** `docs/final/P40_USER_EXPERIENCE_REVIEW.md`  
**Classification:** Frontend Quality & Usability Audit  
**Date:** October 2026  

---

## 1. Usability Review Objectives & Design System

The SnareSight user interface is engineered for high-velocity Security Operations Center (SOC) workflows. It prioritizes dark-theme situational awareness, clear visual hierarchy, instant feedback, and unambiguous forensic inspection.

### Core Design System Foundations:
* **Palette:** Deep slate/navy background (`#0f172a`), crisp text contrast (`#f8fafc`), semantic alert tokens (Cyan for telemetry, Emerald for resolved, Amber for medium risk, Rose for critical alerts).
* **Typography:** Clean sans-serif (`Inter`, `system-ui`) with monospace font (`JetBrains Mono`, `Consolas`) for IP addresses, hashes, and CLI scripts.
* **Component Library:** Tailwind CSS utilities, Lucide React icons, Recharts time-series visualizers, and React Flow (@xyflow/react) node canvases.

---

## 2. Page-by-Page Usability & Interaction Inspection

| Screen / Page | URL Route | Key Interaction Verified | Loading & Empty States | Usability Rating |
|---|---|---|---|---|
| **Authentication Screen** | `/login` | JWT login, input validation, role badge display. | Clear error toast on invalid credentials. | **EXCELLENT** |
| **Overview Dashboard** | `/` | Real-time KPI cards, SSE live alert feed, decoy grid. | Skeleton loaders on fetch; zero flickering. | **EXCELLENT** |
| **Alerts Queue** | `/alerts` | Severity filter, triage drawer, status updates. | Informative empty state when 0 alerts match. | **EXCELLENT** |
| **Security Events Explorer** | `/events` | Paginated event list, JSON payload modal, search. | Fast table rendering with debounce search. | **EXCELLENT** |
| **Session Explorer** | `/sessions` | Grouped sessions, chronological event timeline. | Visual timeline with timestamp deltas. | **EXCELLENT** |
| **Attack Chain Graph** | `/attack-chains` | Interactive React Flow DAG, node dragging, zoom. | Interactive canvas with minimap and controls. | **EXCELLENT** |
| **MITRE ATT&CK Matrix** | `/mitre` | 14-tactic Enterprise grid, heatmapped technique cells. | Technique drawer with mapped detection rules. | **EXCELLENT** |
| **Threat Actor Profiles** | `/sources` | Offender dossiers, threat scores, behavioral tags. | Visual risk score bar and similar IP cards. | **EXCELLENT** |
| **Investigation Workspace** | `/cases` | Case details, analyst notes, retention hold toggle. | Tabbed interface separating evidence & actions. | **EXCELLENT** |
| **Defensive Containment** | `/cases/{id}` | One-click firewall blocking script generation. | Formatted CLI block with "Copy Script" button. | **EXCELLENT** |
| **Sensor Management** | `/sensors` | Decoy health cards, token rotation modal. | Live status badges (`HEALTHY`, `OFFLINE`). | **EXCELLENT** |
| **Analytics & Reporting** | `/reports` | Executive summary KPI charts, PDF report export. | Direct browser download of generated PDF. | **EXCELLENT** |
| **Demonstration Lab** | `/demo` | Scenario trigger cards (SCN-A to SCN-F), cleanup. | Live progress indicators and quality matrix. | **EXCELLENT** |
| **Platform Health** | `/health` | Diagnostic metrics, queue depth, backup status. | Real-time memory and DB pool gauges. | **EXCELLENT** |

---

## 3. Verification of 14 Key Usability Invariants

1. **Pages Load Without Runtime Errors:** Verified. All routes mount cleanly without unhandled React exceptions or console errors.
2. **Navigation Integrity:** Verified. Sidebar links provide immediate routing with active route highlights.
3. **Responsive Layout:** Verified. CSS Grid and Flexbox layouts adapt smoothly from $1920 \times 1080$ desktop displays down to tablet viewports.
4. **Real Backend Data:** Verified. All tables render data returned by FastAPI endpoints; zero hardcoded mock arrays in production views.
5. **Filter Precision:** Verified. Filtering by severity (`HIGH`, `CRITICAL`) or status (`NEW`, `INVESTIGATING`) updates tables instantly.
6. **Form Validation:** Verified. Empty password or invalid username fields trigger red inline validation banners before HTTP dispatch.
7. **Loading State Clarity:** Verified. Tables display subtle pulsing skeleton loaders during background asynchronous fetches.
8. **Empty State Guidance:** Verified. When a queue is empty, screens display helpful illustrations (e.g. *"No unaddressed alerts. Decoy perimeter is nominal."*).
9. **Error State Resilience:** Verified. If an API request fails, a dismissible toast notification appears with a clear error explanation and retry button.
10. **Actionable Buttons:** Verified. Buttons provide visual hover effects, active click states, and disabled states during network requests to prevent double submissions.
11. **Authorization Visibility:** Verified. Administrative functions (such as user creation or backup restoration) are hidden from analysts lacking the `admin` role.
12. **Synthetic Data Identification:** Verified. Events generated in the Demonstration Lab carry an unmistakable `[SYNTHETIC DEMO]` badge.
13. **Forensic Inspection Accessibility:** Verified. Plaintext passwords are displayed as `[REDACTED]`, while raw payload hashes and headers are viewable in one click.
14. **Analyst Workflow Simplicity:** Verified. Escalating an alert to an incident case and generating a firewall blocking command takes $< 4\text{ clicks}$.

