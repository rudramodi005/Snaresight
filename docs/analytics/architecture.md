# SnareSight: Analytics Architecture & Data Flow

**Phase:** 6 — Security Operations Center (SOC) Dashboard  
**Task:** P30 / 40  
**Status:** `COMPLETED AND VERIFIED`

---

## 1. Architectural Overview

The SnareSight Analytics and Reporting module acts as the analytical aggregation layer atop the platform's deception pipeline and operational databases.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                          Data Ingestion Tier                           │
│  [ Honeypots ] ──> [ Raw Events ] ──> [ Normalizer ] ──> [ Deduplicator ]
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        Primary Data Storage                            │
│  • security_events        • alerts               • activity_sessions   │
│  • source_profiles        • investigation_clusters • attack_techniques │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 Analytics Aggregation Engine (Service)                  │
│                                                                        │
│  • Time-Bucket Interval Calculators (minute / hour / day)              │
│  • Previous-Period Comparison Engine (offset window queries)           │
│  • Severity & Confidence Independence Evaluator                        │
│  • Deterministic Executive Narrative Synthesizer                       │
│  • ReportLab PDF Compiler & RFC 4180 CSV Generator                    │
│  • Sensitive Credential / Header Redaction Filter                      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                            REST API Tier                               │
│  GET  /api/v1/analytics/overview                                       │
│  GET  /api/v1/analytics/events/timeline                                │
│  GET  /api/v1/analytics/alerts/timeline                                │
│  GET  /api/v1/analytics/event-alert-overview                           │
│  GET  /api/v1/analytics/detections                                     │
│  GET  /api/v1/analytics/severity                                       │
│  GET  /api/v1/analytics/confidence                                     │
│  GET  /api/v1/analytics/sessions                                       │
│  GET  /api/v1/analytics/sources                                        │
│  GET  /api/v1/analytics/investigations                                 │
│  GET  /api/v1/analytics/attack-coverage                                │
│  GET  /api/v1/analytics/sensors                                        │
│  GET  /api/v1/analytics/pipeline-health                                │
│  GET  /api/v1/analytics/executive-summary                              │
│  POST /api/v1/reports/generate                                         │
│  GET  /api/v1/reports/{report_id}                                      │
│  GET  /api/v1/reports/{report_id}/download                             │
└───────────────────────────────────┬────────────────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 Frontend UI (React + Tailwind CSS)                     │
│  • Time-Window Selector (15m, 1h, 24h, 7d, 30d, custom)                │
│  • Dynamic Global Filters (sensor, category, severity, etc.)           │
│  • 8 Metric KPI Cards with Previous-Period Trend Indicators            │
│  • 8 Focused Analytical Tabs (Trends, Rules, Severity, Sessions, etc.) │
│  • One-Click PDF/CSV Report Generation & Download                      │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. In-Memory Aggregation Strategy

To maintain maximum performance and avoid stale caches:
1. **Dynamic Interval Granularity**: The backend automatically determines the aggregation interval based on the selected time window:
   - Window $\le 1$ hour: Group by 1-minute buckets (`minute`).
   - Window $\le 24$ hours: Group by 1-hour buckets (`hour`).
   - Window $> 24$ hours: Group by 1-day buckets (`day`).
2. **Previous-Period Comparison**: For any window $[T_{start}, T_{end}]$ with duration $\Delta = T_{end} - T_{start}$, the baseline comparison period is strictly $[T_{start} - \Delta, T_{start}]$.
3. **Database Dialect Independence**: The engine utilizes standard SQL functions compatible across both development/testing SQLite engines and production PostgreSQL instances.

