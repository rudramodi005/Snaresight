# Mapping Coverage Analytics & Metrics

## Coverage Metrics Definitions
SnareSight tracks two distinct coverage vectors to evaluate detection capabilities:

### 1. Rule-Based Catalogue Coverage
Measures the breadth of configured detection rules across the Enterprise ATT&CK framework:
$$\text{Overall Rule Coverage \%} = \left(\frac{\text{Unique Techniques with Active Rule Mappings}}{\text{Total Techniques in Active Catalogue}}\right) \times 100$$

### 2. Alert Evidence-Supported Coverage
Measures how many techniques have been empirically observed and validated by live honeypot telemetry:
$$\text{Overall Alert Coverage \%} = \left(\frac{\text{Unique Techniques with Live Alert Evidence}}{\text{Total Techniques in Active Catalogue}}\right) \times 100$$

## Tactic-Level Breakdown
Coverage is computed independently for each of the 14 Enterprise tactics:
- `total_techniques`: Number of Enterprise techniques categorized under this tactic.
- `rule_mapped_techniques`: Techniques with at least one active detection mapping in this tactic.
- `alert_supported_techniques`: Techniques with at least one live alert hit under this tactic.
- `rule_coverage_pct`: Proportion of tactic covered by rules.
- `alert_coverage_pct`: Proportion of tactic validated by live alerts.

## Reporting API
GET `/api/v1/attack/coverage` returns both global coverage statistics and the per-tactic array, used by the Coverage Analytics tab to render progress meters and distribution tables.

