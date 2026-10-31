# SnareSight: Detection Rule Analytics & Performance

**Phase:** 6 — Security Operations Center (SOC) Dashboard  
**Task:** P30 / 40  
**Status:** `COMPLETED AND VERIFIED`

---

## 1. Detection Rule Performance & Distribution

The detection analytics endpoint (`GET /api/v1/analytics/detections`) evaluates rule trigger frequencies, alert distribution across categories, and dormant rule health.

### Metrics Computed
1. **Top Triggered Detection Rules**:
   - Ranked list of detection rules generating alerts in the selected window.
   - Includes Rule ID, Rule Name, Detection Category, Default Severity, and Trigger Count.
2. **Category Distribution**:
   - Total alerts grouped by detection category (e.g. `CREDENTIAL_ACCESS`, `LATERAL_MOVEMENT`, `PERSISTENCE`, `DEFENSE_EVASION`, `RECONNAISSANCE`).
3. **Inactive & Dormant Rules**:
   - Rules enabled in the system that have generated zero alerts during the selected time period.
   - Displays the last known trigger timestamp (or `Never` if fresh).
4. **Analytical Caution / Performance Caveat**:
   - The UI and API explicitly communicate: *High trigger counts may indicate noisy sensors, aggressive automated scanners, or overly broad rule criteria, while low trigger counts do not inherently guarantee the absence of malicious activity.*

