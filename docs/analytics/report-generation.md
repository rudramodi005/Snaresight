# SnareSight: Security Report Generation & Redaction Engine

**Phase:** 6 — Security Operations Center (SOC) Dashboard  
**Task:** P30 / 40  
**Status:** `COMPLETED AND VERIFIED`

---

## 1. Export Formats & Standards

The SnareSight reporting engine (`POST /api/v1/reports/generate`) supports two primary enterprise export formats:

1. **Executive PDF Reports (`PDF`)**:
   - Compiled in-memory using `ReportLab 5.0.0` (zero disk write dependency).
   - Clean professional typography with tables, executive narrative summary, KPI overview matrices, top alert tables, and compliance disclaimers.
2. **Tabular CSV Reports (`CSV`)**:
   - RFC 4180 compliant CSV export format suitable for SIEM, spreadsheet, and external BI tool consumption.
   - Contains metadata header block, summary KPI counts, and detailed alert records with timestamps, severities, and source IP indicators.

---

## 2. Sensitive Field Redaction

To prevent sensitive decoy secrets, session authorization tokens, or internal credentials from being inadvertently exposed in exported PDF or CSV artifacts, the reporting service runs a deterministic redaction sanitizer:

```python
REDACTION_PATTERNS = [
    (r'(?i)(password|secret|token|api_key|authorization)\s*[:=]\s*["\']?([^"\'\s]+)["\']?', r'\1: [REDACTED]'),
    (r'(?i)bearer\s+[a-zA-Z0-9_\-\.]+', 'Bearer [REDACTED]'),
    (r'(?i)(authorization:\s*basic\s+)[a-zA-Z0-9+/=]+', r'\1[REDACTED]')
]
```

Any payloads or event headers containing authentication secrets are redacted prior to embedding into the report output.

---

## 3. Database Audit Logging

Every generated report is permanently recorded in the database `security_reports` table:
- `id`: Unique UUID primary key.
- `report_title`: Analyst-provided or default title.
- `report_type`: `EXECUTIVE_SUMMARY`, `DETECTION_ANALYSIS`, or `FULL_INCIDENT_AUDIT`.
- `time_range_label`: Selected time range (e.g. `24h`, `7d`).
- `start_time` & `end_time`: UTC timestamps defining the audit boundary.
- `generated_by`: Authenticated analyst identity (e.g., `soc_lead`).
- `file_format`: `PDF` or `CSV`.
- `filters_applied`: JSON record of all filter parameters applied during generation.
- `summary_metrics`: JSON snapshot of core KPIs at time of generation.
- `file_size_bytes`: Byte length of generated document.
- `pdf_content`: Binary payload stored as SQL `LargeBinary` / `BYTEA`.
- `csv_content`: Text payload stored as SQL `Text`.
- `status`: `COMPLETED` or `FAILED`.
- `created_at`: Generation timestamp in UTC.

Reports can be fetched by ID via `GET /api/v1/reports/{report_id}` and streamed directly to the browser via `GET /api/v1/reports/{report_id}/download`.

