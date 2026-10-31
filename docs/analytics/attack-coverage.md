# SnareSight: MITRE ATT&CK Analytics & Coverage Tracking

**Phase:** 6 — Security Operations Center (SOC) Dashboard  
**Task:** P30 / 40  
**Status:** `COMPLETED AND VERIFIED`

---

## 1. Matrix Coverage Metrics

The ATT&CK coverage endpoint (`GET /api/v1/analytics/attack-coverage`) provides visibility into enterprise deception coverage against the MITRE ATT&CK framework:

1. **Total Catalogue Techniques**: Techniques present in the local MITRE STIX repository.
2. **Techniques with Rule Mappings**: Catalogue techniques covered by at least one enabled detection rule.
3. **Techniques with Active Alerts**: Techniques actively observed and substantiated by alerts during the selected analysis window.
4. **Unmapped Active Detection Rules**: Enabled detection rules lacking an explicit, approved MITRE mapping definition.
5. **Tactic Breakdown**: Aggregate alert counts categorized across the 14 enterprise tactics:
   - Initial Access
   - Execution
   - Persistence
   - Privilege Escalation
   - Defense Evasion
   - Credential Access
   - Discovery
   - Lateral Movement
   - Collection
   - Command and Control
   - Exfiltration
   - Impact

Direct one-click navigation links connect analysts from this analytics tab into the full interactive MITRE ATT&CK Matrix view (`/mitre`).

