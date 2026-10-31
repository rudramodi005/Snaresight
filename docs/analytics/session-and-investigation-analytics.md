# SnareSight: Session & Investigation Analytics

**Phase:** 6 — Security Operations Center (SOC) Dashboard  
**Task:** P30 / 40  
**Status:** `COMPLETED AND VERIFIED`

---

## 1. Session Duration & Event Volume Analytics

The session intelligence endpoint (`GET /api/v1/analytics/sessions`) measures the behavioral characteristics of correlated interaction sessions:

### Duration Distribution
- **Flash Probes**: `< 1 min` (automated port scans, single HTTP probes).
- **Short Interactions**: `1 - 5 min` (automated credential brute forcing, initial banners).
- **Extended Engagement**: `5 - 30 min` (multi-stage script execution, command injection).
- **Persistent Engagement**: `> 30 min` (human interactive sessions, advanced multi-session lateral exploration).

### Event Volume Breakdown
Sessions are categorized by density of recorded events:
- `1 - 5 events`: Single command or probe.
- `6 - 20 events`: Standard scripted interaction.
- `21 - 50 events`: In-depth directory enumeration or file transfer.
- `> 50 events`: Prolonged interactive or automated flooding.

---

## 2. Source Intelligence & Privacy Safeguards

The source analytics endpoint (`GET /api/v1/analytics/sources`) surfaces recurring threat source profiles:
- Profile ID and masked or truncated IP representations.
- Total correlated sessions and total alerts triggered.
- Profile priority level (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).

### Non-Attribution Notice
> **Analytical Constraint Notice**: Source IP addresses and network indicators represent network origins observed by deception sensors. They do **not** constitute definitive legal or physical attribution to specific threat actors due to intermediate proxies, compromised consumer VPNs, cloud egress points, and distributed botnet nodes.

---

## 3. Campaign & Investigation Analytics

The investigations analytics endpoint (`GET /api/v1/analytics/investigations`) tracks clusters across their operational lifecycle:
- Counts by status: `NEW`, `TRIAGED`, `ACTIVE`, `IN_REVIEW`, `RESOLVED`, `CLOSED`.
- Priority distribution: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.
- Associated alert count and linked session count per active campaign.
- Deep-links directly to the Campaign Investigations workspace (`/investigations`).

