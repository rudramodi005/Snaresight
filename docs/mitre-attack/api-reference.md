# MITRE ATT&CK Dashboard API Reference

All endpoints are mounted under `/api/v1/attack` (and aliased under `/api/v1/mitre`).

## GET /api/v1/attack/catalogue/metadata
Returns active dataset version provenance, STIX version, SHA-256 checksum, object counts, and mapping registry version.

## GET /api/v1/attack/summary
Returns high-level SOC dashboard KPIs:
- `total_catalogue_techniques`
- `total_catalogue_subtechniques`
- `total_catalogue_tactics`
- `mapped_techniques_count`
- `supported_by_alerts_count`
- `pending_analyst_review_count`
- `active_detection_rules_mapped`
- `unmapped_detection_rules_count`
- `coverage_percentage`

## GET /api/v1/attack/tactics
Returns the 14 Enterprise ATT&CK tactics in canonical order (`TA0043` through `TA0040`) with technique counts, supporting rules, live alerts, and coverage percentages.

## GET /api/v1/attack/matrix
Query parameters:
- `tactic`: Filter by specific tactic ID
- `status_filter`: `ALL`, `ALERT_EVIDENCE`, `RULE_MAPPED`, `REVIEW_REQUIRED`, `UNMAPPED`
- `search`: Keyword string matching technique ID or name

Returns column objects corresponding to tactics, each containing an array of technique cell objects with computed `visual_state`.

## GET /api/v1/attack/techniques
Query parameters:
- `search`: Filter by technique ID or name
- `tactic`: Filter by tactic ID
- `platform`: Filter by target platform (e.g. Linux, Windows)
- `status_filter`: Filter by visual state
- `page`: Page number (default: 1)
- `page_size`: Items per page (default: 20)
- `sort_by`: Column to sort by
- `sort_dir`: `asc` or `desc`

Returns paginated list of techniques for the Technique Explorer table.

## GET /api/v1/attack/techniques/{technique_id}
Returns comprehensive details for a single technique:
- Official taxonomy: ID, name, platforms, data sources, description.
- Sub-techniques list.
- Configured SnareSight detection rule mappings.
- Live supporting alert and event evidence with navigation links.
- Mandatory non-attribution caveat.

## GET /api/v1/attack/coverage
Returns overall rule and alert coverage percentages, alongside the full 14-tactic coverage breakdown.

## GET /api/v1/attack/traceability
Query parameters:
- `rule_id`: Optional filter by detection rule ID
- `technique_id`: Optional filter by technique ID

Returns end-to-end traceability chains connecting Technique → Mapping → Rule → Alert → Event → Session.

## POST /api/v1/attack/mappings/{mapping_id}/approve
Submits an approval decision (`ACCEPT`) for a mapping record.
Body:
```json
{
  "action": "APPROVE",
  "comment": "Verified credential guessing pattern against cowrie honeypot",
  "analyst_id": "analyst_soc_user"
}
```

## POST /api/v1/attack/mappings/{mapping_id}/reject
Submits a rejection decision (`REJECT`) for a mapping record.

## POST /api/v1/attack/mappings/{mapping_id}/request-review
Submits a review request (`REQUEST_MORE_EVIDENCE`) for ambiguous mappings.

