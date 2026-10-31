# SnareSight Complete Bug Register

**Audit Date:** November 1, 2026  
**Auditor:** QA Automation & Systems Engineer  
**Registry Status:** All identified bugs remediated and verified.

---

## Bug Inventory Summary

| Bug ID | Subsystem | Severity | Description | Status |
| :--- | :--- | :--- | :--- | :--- |
| **BUG-001** | Docker / Backend | **Critical** | Backend build failure: `uv pip install` failed due to missing virtual environment. | **RESOLVED** |
| **BUG-002** | Docker / Frontend | **High** | Frontend health check failed because `localhost` resolved to IPv6 `[::1]` while Nginx listened on IPv4 `127.0.0.1`. | **RESOLVED** |
| **BUG-003** | Frontend / MITRE | **Critical** | Blank screen crash (`TypeError: Cannot read properties of undefined (reading 'toFixed')`) when viewing technique coverage. | **RESOLVED** |
| **BUG-004** | Backend / Database | **High** | Psycopg driver mismatch (`psycopg` vs `psycopg2`) in database session factory. | **RESOLVED** |
| **BUG-005** | Backend / MITRE | **Medium** | Technique catalogue was unseeded on fresh database starts, causing empty matrix rendering. | **RESOLVED** |
| **BUG-006** | Backend / Demo | **High** | Scenario reset threw HTTP 500 error due to `ForeignKeyViolation` on `activity_session_events`. | **RESOLVED** |
| **BUG-007** | Frontend / MITRE | **High** | `TypeError: Cannot read properties of undefined (reading 'slice')` on `tech.platforms` in Technique Explorer tab. | **RESOLVED** |
| **BUG-008** | Frontend / MITRE | **Medium** | Schema attribute mismatches in Technique Detail drawer (`supporting_evidence` vs `live_evidence`). | **RESOLVED** |
| **BUG-009** | Database / Alembic | **High** | `alembic_version` table was missing/unstamped, causing `alembic upgrade head` to fail with `DuplicateTable: honeypots`. | **RESOLVED** |
| **BUG-010** | Frontend / Format | **High** | Unsafe `.toLocaleString()` on undefined metrics in `SecurityAnalyticsPage.tsx` and `SecurityEventsPage.tsx`. | **RESOLVED** |
| **BUG-011** | Frontend / Chains | **Medium** | Potential `TypeError` on `.map()` when API returns null nested arrays in Analytics, Mappings, and Sessions views. | **RESOLVED** |
| **BUG-012** | Frontend / Responsive | **Medium** | Sidebar was static on mobile screens (< 768px), squeezing page content down to unreadable widths. | **RESOLVED** |
| **BUG-013** | Frontend / Design | **High** | Hardcoded multi-color SVGs and default Tailwind palettes conflicted with the strict `#000F08` / `#FB3640` brand rule. | **RESOLVED** |
| **BUG-014** | Frontend / Typing | **Low** | `BrandLogo` prop `size` restricted to string literals, rejecting numeric pixel dimensions. | **RESOLVED** |

---

## Total Counts
- **Total Defects Discovered:** 14
- **Total Defects Remediated:** 14
- **Remaining Blocking Defects:** 0
- **Regression Verification:** All 535 backend tests and 26 frontend tests pass cleanly.

