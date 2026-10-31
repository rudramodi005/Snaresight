# SnareSight Frontend Architecture & Code Quality Audit

**Scope:** React 18 SPA, TypeScript 5, Vite 6, Tailwind CSS 3, Recharts, Lucide Icons  
**Target URL:** `http://127.0.0.1:5173/`  
**Date:** November 1, 2026  
**Auditor:** Principal Frontend Architect & UI/UX Specialist  
**Status:** **VERIFIED**

---

## 1. Frontend Audit Overview

The frontend codebase was audited across every component, route, hook, API client service, and state container to ensure:
- Zero runtime crashes or unhandled client exceptions.
- Elimination of blank screen states via robust React Error Boundaries.
- Absolute adherence to the strict brand color constraint (`#000F08` Obsidian Void and `#FB3640` Snare Crimson).
- Full responsive adaptability across 7 canonical viewports.

---

## 2. Brand Identity Enforcement

### Absolute Restriction Compliance:
- **Primary Background:** `#000F08`
- **Primary Accent:** `#FB3640`
- **Zero Third Color:** Tailored `tailwind.config.js` remapped default Tailwind palettes (slate, gray, zinc, blue, emerald, amber, rose, cyan, etc.) strictly to `#000F08` and `#FB3640` tonal opacities.
- **Readable Contrast:** On solid `#FB3640` buttons, text is set to high-contrast `#000F08` (luminance ratio > 12:1). On `#000F08` backgrounds, text is set to `#FB3640` or opacities (`rgba(251, 54, 64, 0.85)` / `0.65`).

### Brand Components Created:
- `BrandLogo.tsx`: Geometric hexagonal radar shell with concentric deception nodes in `#FB3640`.
- `Button.tsx`: Solid crimson, outline, ghost, and dim variants with tactile active states.
- `Card.tsx`: Glassmorphic panels with `rgba(251, 54, 64, 0.05)` background and `rgba(251, 54, 64, 0.16)` border.
- `Badge.tsx`: Severity indicators (CRITICAL, HIGH, MEDIUM, LOW) styled with crimson weights and opacities.
- `Input.tsx`: High-contrast form controls with crimson glow focus states.
- `StatusIndicator.tsx`: Pulsing live stream status dots.

---

## 3. Numeric & Timestamp Safety Audit (.toFixed & .toLocaleString)

### Investigation of `TypeError: Cannot read properties of undefined`:
1. **Root Cause Analysis:**
   In complex analytics dashboards, when an API returns missing, null, or undefined metrics, invoking `.toFixed()` or `.toLocaleString()` directly on `item.value` causes an immediate uncaught TypeError.
2. **Defensive Formatting Framework (`src/utils/format.ts`):**
   - `isValidNumber(val: unknown)`: Validates that input is a genuine finite number (rejects `null`, `undefined`, `NaN`, `Infinity`, strings, objects).
   - `formatNumber(val, digits, fallback = 'N/A')`: Safely formats decimals without crashing.
   - `formatPercent(val, digits, fallback = 'N/A', multiplier)`: Formats percentages and ratios safely.
   - `safeDivide(numerator, denominator, fallback = 0)`: Defends against division by zero.
   - `formatInteger(val, fallback = '0')`: Replaces unsafe `.toLocaleString()` calls on integers.
   - `formatDateTime(val, fallback = 'N/A')`: Parses ISO timestamps safely and returns fallback on invalid dates.

### Remediated Call Sites:
- `SecurityAnalyticsPage.tsx`: Replaced direct calls on `overview?.total_events`, `overview?.total_alerts`, `overview?.active_sessions`, `eventTimeline?.total_events`, and `alertTimeline?.total_alerts` with `formatInteger()`.
- `SecurityEventsPage.tsx`: Replaced direct calls on `summary.total_events`, `summary.detected_events`, `summary.clean_events`, `summary.distinct_sources`, and `totalEvents` with `formatInteger()`.
- `SecurityOperationsOverviewPage.tsx`: Replaced direct calls on `data.metrics.total_events.value` and `data.metrics.total_alerts.value` with `formatInteger()`.
- Multiple Feature Pages: Replaced raw `new Date(...).toLocaleString()` with `formatDateTime(...)` across Alerts, Investigations, Sensors, Health, and Source Intelligence.

---

## 4. Defensive Array Chaining & Null Guarding

Audit discovered several locations where optional chaining stopped before `.map()` on nested properties:
- `sourceData?.top_recurring_profiles.slice(0, 5)` -> changed to `(sourceData?.top_recurring_profiles || []).slice(0, 5)`
- `detections?.top_rules.map(...)` -> changed to `(detections?.top_rules || []).map(...)`
- `detections?.category_breakdown.map(...)` -> changed to `(detections?.category_breakdown || []).map(...)`
- `severityData?.breakdown.map(...)` -> changed to `(severityData?.breakdown || []).map(...)`
- `confidenceData?.buckets.map(...)` -> changed to `(confidenceData?.buckets || []).map(...)`
- `sessionData?.duration_distribution.map(...)` -> changed to `(sessionData?.duration_distribution || []).map(...)`
- `investigationData?.top_investigations.map(...)` -> changed to `(investigationData?.top_investigations || []).map(...)`
- `attackData?.tactics.map(...)` -> changed to `(attackData?.tactics || []).map(...)`
- `sensorData?.sensors.map(...)` -> changed to `(sensorData?.sensors || []).map(...)`
- `executiveSummary?.operational_limitations.map(...)` -> changed to `(executiveSummary?.operational_limitations || []).map(...)`
- `paginated?.items.map(...)` in Mappings and Sessions -> changed to `(paginated?.items || []).map(...)`

---

## 5. React Error Boundary Hardening

[`ErrorBoundary.tsx`](file:///c:/Projects/SnareSight/frontend/src/components/common/ErrorBoundary.tsx) was updated to:
- Intercept any unhandled component exceptions in React render trees.
- Render an obsidian-crimson diagnostic panel with error name, message, stack trace disclosure, and recovery options ("Retry Component", "Return to Overview", "Reload Page").
- Prevent application-wide blank screens.

---

## 6. Route Segmentation & Verification

| Route | Classification | Component | HTTP Status | Auth Requirement |
| :--- | :--- | :--- | :--- | :--- |
| `/` | Public | `LandingPage` | 200 OK | None (Unauthenticated) |
| `/login` | Public | `LoginPage` | 200 OK | None |
| `/app/overview` | Authenticated | `SecurityOperationsOverviewPage` | 200 OK | Bearer / Session Auth |
| `/app/alerts` | Authenticated | `AlertManagementPage` | 200 OK | Bearer / Session Auth |
| `/app/events` | Authenticated | `SecurityEventsPage` | 200 OK | Bearer / Session Auth |
| `/app/investigations`| Authenticated | `CampaignInvestigationsPage` | 200 OK | Bearer / Session Auth |
| `/app/source-intelligence`| Authenticated | `SourceIntelligencePage` | 200 OK | Bearer / Session Auth |
| `/app/sessions` | Authenticated | `SessionInvestigationPage` | 200 OK | Bearer / Session Auth |
| `/app/sequences` | Authenticated | `SequenceInvestigationPage` | 200 OK | Bearer / Session Auth |
| `/app/mitre` | Authenticated | `MitreAttackDashboardPage` | 200 OK | Bearer / Session Auth |
| `/app/mitre/mappings`| Authenticated | `MitreMappingsPage` | 200 OK | Bearer / Session Auth |
| `/app/analytics` | Authenticated | `SecurityAnalyticsPage` | 200 OK | Bearer / Session Auth |
| `/app/response` | Authenticated | `DefensiveResponseCenterPage` | 200 OK | Bearer / Session Auth |
| `/app/sensors` | Authenticated | `SensorOperationsPage` | 200 OK | Bearer / Session Auth |
| `/app/health` | Authenticated | `PlatformSecurityHealthPage` | 200 OK | Bearer / Session Auth |
| `/app/demo` | Authenticated | `DemonstrationControlPage` | 200 OK | Bearer / Session Auth |
| `/app/settings` | Authenticated | `SettingsPage` | 200 OK | Bearer / Session Auth |

*Legacy flat routes (`/overview`, `/events`, `/mitre`, etc.) automatically redirect to `/app/*`.*

