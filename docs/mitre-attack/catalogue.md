# MITRE ATT&CK Catalogue Management & Versioning

## Active Catalogue Specification
- **Framework Domain**: `enterprise-attack`
- **Active Release Version**: `v14.1`
- **STIX Specification**: 2.1
- **Source Artifact**: `backend/app/modules/mitre/data/enterprise-attack-v14.1.json`
- **Auto-Initialization**: `AttackDashboardService.ensure_catalogue_initialized` verifies whether catalogue tables contain objects. If empty (such as upon fresh deployment or automated testing), it parses and imports the bundled release idempotently.

## Integrity and Provenance
Each imported dataset release produces a persistent record in `attack_dataset_versions` containing:
- `sha256_checksum`: Cryptographic fingerprint of the ingested bundle.
- `object_count`: Total parsed objects including tactics, techniques, and relationships.
- `retrieval_date` and `release_date`: Provenance timestamps.
- `is_active`: Flag designating the authoritative version used for queries and dashboard metrics.

## Supported STIX Object Types
- `x-mitre-tactic`: Enterprise tactic definitions.
- `attack-pattern`: Enterprise techniques and sub-techniques.
- `relationship`: `subtechnique-of` linkages connecting child techniques to parents.
- `kill-chain-phases`: Association connecting techniques to tactics.

