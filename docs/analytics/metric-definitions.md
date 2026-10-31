# SnareSight: Metric Definitions, Formulas & Comparison Rules

**Phase:** 6 — Security Operations Center (SOC) Dashboard  
**Task:** P30 / 40  
**Status:** `COMPLETED AND VERIFIED`

---

## 1. Overview KPI Cards

The analytics overview provides eight foundational operational metrics calculated dynamically over the selected time window:

| KPI Metric | Underlying Entity | Calculation Formula | Previous-Period Comparison |
| :--- | :--- | :--- | :--- |
| **Total Observed Events** | `security_events` | `COUNT(*)` where `observed_at BETWEEN start AND end` | Delta percentage against previous window |
| **Total Generated Alerts**| `alerts` | `COUNT(*)` where `generated_at BETWEEN start AND end` | Delta percentage against previous window |
| **Critical Alerts** | `alerts` | `COUNT(*)` where `severity = 'CRITICAL'` | Delta percentage against previous window |
| **High-Severity Alerts** | `alerts` | `COUNT(*)` where `severity = 'HIGH'` | Delta percentage against previous window |
| **Active Sessions** | `activity_sessions` | `COUNT(*)` where `last_activity_at >= start AND first_observed_at <= end` | Delta percentage against previous window |
| **Suspicious Sessions** | `activity_sessions` | `COUNT(*)` where `highest_severity IN ('CRITICAL', 'HIGH')` | Delta percentage against previous window |
| **Active Investigations** | `investigation_clusters` | `COUNT(*)` where `lifecycle_status IN ('NEW', 'TRIAGED', 'ACTIVE', 'IN_REVIEW')` | Delta percentage against previous window |
| **Reporting Sensors** | `honeypots` | `COUNT(DISTINCT decoy_id)` of active honeypots receiving events | Delta percentage against previous window |

---

## 2. Trend & Delta Formulas

For any metric $M$, let:
- $V_{current}$: Value in the current window $[T_{start}, T_{end}]$ with duration $D = T_{end} - T_{start}$.
- $V_{prev}$: Value in the prior window $[T_{start} - D, T_{start}]$.

### Percentage Change Formula
$$\Delta\% = \begin{cases} 0.0 & \text{if } V_{prev} = 0 \text{ and } V_{current} = 0 \\ 100.0 & \text{if } V_{prev} = 0 \text{ and } V_{current} > 0 \\ \frac{V_{current} - V_{prev}}{V_{prev}} \times 100 & \text{otherwise} \end{cases}$$

---

## 3. Event-to-Alert Conversion Density

The conversion density quantifies how honeypot telemetry is filtered into actionable alerts:

$$\text{Conversion Ratio} = \begin{cases} 0.0 & \text{if Total Events} = 0 \\ \frac{\text{Total Alerts}}{\text{Total Events}} & \text{otherwise} \end{cases}$$

$$\text{Suppression Rate} = (1.0 - \text{Conversion Ratio}) \times 100\%$$

A low conversion ratio (e.g., $1:50$ or $2\%$) signifies high noise suppression efficiency, indicating that honeypot probes and background noise are being effectively filtered before alert promotion.

