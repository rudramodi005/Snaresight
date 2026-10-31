# SnareSight: Presentation & Academic Review Readiness Checklist

**Document Version:** 1.0.0  
**Phase:** 8 — Testing, Demonstration & Project Handover  
**Document:** `docs/final/PRESENTATION_READINESS_CHECKLIST.md`  
**Status:** ALL CHECKS VERIFIED & READY FOR REVIEW  

---

## 1. Master Readiness Verification Matrix

| Verification Item | Requirement Description | Verification Evidence | Status |
|---|---|---|---|
| **1. Application Startup** | Backend & Frontend launch without fatal crashes or unresolved imports. | `uvicorn app.main:app` and `npm run dev` launch in $< 3\text{ seconds}$. | **VERIFIED** |
| **2. Database Connectivity** | PostgreSQL / SQLite memory engines connect and apply full schema. | `alembic current` confirms revision `p34_operational_resilience`. | **VERIFIED** |
| **3. Demonstration Harness** | Deterministic attack scenarios (SCN-A to SCN-F) execute safely offline. | Tested via `tests/test_demo_api.py` (11/11 pass). | **VERIFIED** |
| **4. End-to-End Workflow** | Ingestion $\to$ Detection $\to$ Alert $\to$ MITRE $\to$ DAG $\to$ Containment works end-to-end. | Verified in `tests/test_e2e_workflows.py` (8/8 pass). | **VERIFIED** |
| **5. Live Browser Pages** | Overview, Alerts, Sessions, Attack Chains, MITRE, Cases, Demo render cleanly. | 9 Vitest tests pass; production bundle builds cleanly. | **VERIFIED** |
| **6. Architecture Diagrams** | 5 detailed Mermaid flowcharts and sequence diagrams match actual code. | Available in `docs/documentation/SYSTEM_ARCHITECTURE.md`. | **VERIFIED** |
| **7. Slide Deck Content** | 15 structured slides covering all 5 criteria with slide-by-slide speaker notes. | Authored in `docs/final/P39_PRESENTATION_CONTENT.md`. | **VERIFIED** |
| **8. Timed Demo Script** | 5–8 minute timed script detailing exact words, clicks, and fallbacks. | Authored in `docs/final/PRESENTATION_DEMONSTRATION_SCRIPT.md`. | **VERIFIED** |
| **9. Reviewer Q&A Defense** | 30 rigorous questions across all criteria with technically defensible answers. | Authored in `docs/final/LIKELY_REVIEWER_QUESTIONS.md`. | **VERIFIED** |
| **10. Limitations Disclosed** | Explicit disclosure of deferred rules (`CMD-001`, `FILE-001`) and bundle chunk size. | Fully documented in `docs/final/05_CURRENT_PROGRESS.md`. | **VERIFIED** |
| **11. Offline Fallback Ready** | Can execute the complete evaluation without live Internet access. | Docker Compose / local venv runs 100% offline with zero external CDNs. | **VERIFIED** |
| **12. Zero Secrets Exposed** | No private keys, passwords, or live enterprise IP addresses in slides/docs. | Checked via security review; RFC 5737 dummy addresses used throughout. | **VERIFIED** |
| **13. No Unsupported Claims** | No claims of global uniqueness or AI magic without measured evidence. | Evaluated honestly in `docs/final/04_INNOVATION_AND_CREATIVITY.md`. | **VERIFIED** |

---

## 2. Day-of-Presentation Quick-Checklist (T - 15 Minutes)

Complete this 8-step checklist 15 minutes before taking the podium:

- [ ] **Step 1: Power & Display Setup:** Connect laptop to projector/display; ensure resolution is set to $1920 \times 1080$ and display scaling is $100\%$ or $125\%$.
- [ ] **Step 2: Start Containers:** Launch services via terminal:
  ```powershell
  cd c:\Projects\SnareSight
  docker compose up -d
  ```
- [ ] **Step 3: Verify Health:** Check container status in browser:
  * Open `http://localhost:8000/health` (must return `"status":"OPERATIONAL"`).
- [ ] **Step 4: Open Browser Tabs:**
  * Tab 1: Slide Deck / Presentation notes.
  * Tab 2: `http://localhost:5173/` (Overview Dashboard).
  * Tab 3: `http://localhost:5173/demo` (Demonstration Lab).
  * Tab 4: `http://localhost:8000/docs` (Swagger UI fallback).
- [ ] **Step 5: Pre-Authenticate:** Log into the dashboard as `analyst@snaresight.local`.
- [ ] **Step 6: Reset Demo Lab:** Navigate to `/demo` and click **Clean Demonstration Data** to ensure a fresh, pristine queue.
- [ ] **Step 7: Check Terminal Window:** Keep one terminal open in the background to show live server logs or run Pytest if requested by evaluators.
- [ ] **Step 8: Deep Breath & Focus on Evidence:** Remember that every claim in the presentation is supported by real code and automated tests.

