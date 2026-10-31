# SnareSight: SOC Analytics, Security Reporting & Executive Overview

**Module:** SOC Analytics, Security Reporting, and Executive Overview  
**Phase:** 6 — Security Operations Center (SOC) Dashboard  
**Task:** P30 / 40  
**Status:** `COMPLETED AND VERIFIED`

---

## 1. Overview & Purpose

The **SnareSight Security Analytics and Reporting Module** provides security operations centers, lead threat hunters, and executive security stakeholders with high-integrity, evidence-based aggregate analytics, longitudinal trend visualizations, and auditable security report exports.

Unlike generic business intelligence platforms or cosmetic security dashboards, this module adheres strictly to the core design principles of SnareSight:
- **No Fabricated Telemetry**: Every chart, percentage delta, and metric card is calculated directly from ground-truth database records (`security_events`, `alerts`, `activity_sessions`, `source_profiles`, `investigation_clusters`, `honeypots`).
- **Separation of Severity and Confidence**: Severity (inherent impact) and Confidence (evidence certainty) are computed and visualized independently across all analytics views.
- **Privacy & Non-Attribution**: External source profiles display mandatory non-attribution notices, cautioning analysts against assuming IP addresses represent confirmed physical threat actors due to proxies, VPNs, and botnets.
- **Deterministic Executive Summaries**: Executive narratives are algorithmically synthesized from actual database metrics—never fabricated or hallucinated.
- **Auditable Report Generation**: Reports are generated synchronously into standard PDF (`reportlab`) or RFC 4180 CSV formats with automatic redaction of sensitive internal tokens and full audit tracking in the database (`security_reports`).

---

## 2. Directory Structure

```text
c:\Projects\SnareSight\
├── backend\
│   ├── app\
│   │   ├── db\models\report.py               # SecurityReportModel
│   │   ├── modules\analytics\
│   │   │   ├── __init__.py                   # Router exports (analytics_router, reports_router)
│   │   │   ├── schemas.py                    # Pydantic schemas for analytics & reporting
│   │   │   ├── service.py                    # AnalyticsService (aggregation, narratives, PDF/CSV generation)
│   │   │   └── routes.py                     # 13 REST endpoints (/api/v1/analytics/*, /api/v1/reports/*)
│   ├── migrations\versions\
│   │   └── p30_security_reports.py           # Alembic migration for security_reports table
│   └── tests\modules\analytics\
│       └── test_analytics_api.py             # 13 unit tests covering analytics & report generation
├── frontend\
│   └── src\
│       ├── types\analytics.ts                # TypeScript interfaces for analytics & reports
│       ├── services\analyticsApi.ts          # API client for analytics & reporting endpoints
│       ├── features\analytics\
│       │   └── SecurityAnalyticsPage.tsx     # Comprehensive SOC Analytics & Reporting UI
│       └── App.tsx                           # Persistent navigation link (/analytics) & route
└── docs\analytics\
    ├── README.md                             # Module overview (this file)
    ├── architecture.md                       # Architectural design & data flow
    ├── metric-definitions.md                 # Definitions, formulas, & comparison rules
    ├── event-and-alert-analytics.md          # Event & alert trend analysis
    ├── detection-analytics.md                # Detection rule performance & distribution
    ├── session-and-investigation-analytics.md# Session & campaign analytics
    ├── attack-coverage.md                    # MITRE ATT&CK coverage tracking
    ├── sensor-and-pipeline-health.md         # Ingestion throughput & sensor freshness
    ├── report-generation.md                  # PDF/CSV generation, redaction & audit
    └── security-and-testing.md               # Security boundaries & automated testing
```

---

## 3. Key Components

1. **Overview KPI Cards**: 8 core operational metrics (Total Observed Events, Total Generated Alerts, Critical Alerts, High-Severity Alerts, Active Sessions, Suspicious Sessions, Active Investigations, Reporting Sensors) with percentage deltas against preceding time windows.
2. **Timeline Visualizations**: Event and Alert temporal trends with discrete time-bucket aggregation (`minute`, `hour`, `day`) and categorical breakdowns (category, protocol, severity, status).
3. **Event-to-Alert Ratio**: Conversion density indicator showing efficiency of honeypot noise suppression and high-signal alert promotion.
4. **Detection Rule Analytics**: Most frequently triggered rules, alert distribution by detection category, and dormant/inactive rules.
5. **Severity vs. Confidence Matrix**: Strict dual-axis visibility preventing false conflation of high-severity low-confidence triggers with low-severity high-confidence events.
6. **Session & Source Profiles**: Duration distribution, event volume per session, and recurring source intelligence with strict privacy boundaries.
7. **Campaign & MITRE ATT&CK Tracking**: Cluster lifecycle breakdown and ATT&CK tactic/technique coverage mapping.
8. **Pipeline & Sensor Health**: Real-time sensor telemetry freshness (`ONLINE`, `STALE`, `INACTIVE`), deduplication volume, and ingestion rate.
9. **Deterministic Executive Briefing**: Natural language narrative synthesizing key findings, top threats, operational posture, and analytical limitations.
10. **Export Engine**: In-memory PDF and CSV generation with automated redaction of sensitive credentials/headers, persisted in `security_reports` table for compliance.

---

## 4. Documentation Index

- [Architecture & Data Flow](file:///c:/Projects/SnareSight/docs/analytics/architecture.md)
- [Metric Definitions & Formulas](file:///c:/Projects/SnareSight/docs/analytics/metric-definitions.md)
- [Event & Alert Analytics](file:///c:/Projects/SnareSight/docs/analytics/event-and-alert-analytics.md)
- [Detection Analytics](file:///c:/Projects/SnareSight/docs/analytics/detection-analytics.md)
- [Session & Investigation Analytics](file:///c:/Projects/SnareSight/docs/analytics/session-and-investigation-analytics.md)
- [MITRE ATT&CK Coverage](file:///c:/Projects/SnareSight/docs/analytics/attack-coverage.md)
- [Sensor & Pipeline Health](file:///c:/Projects/SnareSight/docs/analytics/sensor-and-pipeline-health.md)
- [Report Generation & Redaction](file:///c:/Projects/SnareSight/docs/analytics/report-generation.md)
- [Security & Testing](file:///c:/Projects/SnareSight/docs/analytics/security-and-testing.md)

