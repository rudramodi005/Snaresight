# Source Intelligence Architecture

## System Boundaries & Subsystem Flow

The **Source Intelligence Subsystem** sits downstream of the Event Ingestion Pipeline (P11–P15), Rule Detection Engine (P16–P18), MITRE Mapping (P19–P20), and Session Correlation Engine (P21).

### Key Modules

```
backend/app/modules/source_intelligence/
├── __init__.py           # Subsystem export surface
├── schemas.py            # Pydantic request/response schemas
├── fingerprint.py        # IP canonicalization and deterministic fingerprinting
├── feature_extractor.py  # Statistical and qualitative behavioral metrics
├── prioritization.py     # Deterministic, explainable profile prioritization
├── similarity.py         # Multi-dimensional behavioral similarity analysis
├── recurrence.py         # Dormancy & recurrence pattern detection
├── aggregator.py         # Idempotent database profile aggregation engine
├── service.py            # Business logic and query facades
└── routes.py             # FastAPI REST endpoint routes (/api/v1/source-profiles)
```

### Data Pipeline & Execution Flow

1. **Discovery & Canonicalization (`fingerprint.py`):**
   - Inbound source IP addresses from `SecurityEventModel` and `ActivitySessionModel` are canonicalized using standard RFC representations (`ipaddress.ip_address`).
   - Generates deterministic SHA-256 fingerprint tokens for stable profile association without exposing plaintext identifiers to external systems.
2. **Feature Extraction (`feature_extractor.py`):**
   - Calculates interaction tempos (events per active minute), burstiness ratios (peak 1-minute rate vs average rate), and max concurrent session overlaps.
   - Extracts authentication behavior (attempt count, failure count, distinct usernames probed) strictly without persisting passwords.
   - Measures reconnaissance depth: path traversal probes (`..`, `/etc/passwd`, `cmd.exe`), distinct path targets, and targeted honeypot decoys.
3. **Multi-Window Aggregation (`aggregator.py`):**
   - Computes behavioral feature snapshots across 5 discrete windows: `1H`, `24H`, `7D`, `30D`, and `ALL_TIME`.
   - Maintains junction entries in `source_profile_sessions` idempotently.
4. **Behavioral Similarity Engine (`similarity.py`):**
   - Compares Observed Source Profiles across four dimensions:
     - Target Decoy Affinity (Jaccard similarity)
     - Protocol Vector Distribution (Cosine similarity)
     - MITRE ATT&CK Technique Footprint (Jaccard similarity)
     - Interaction Modulation & Auth Spraying (Numerical difference similarity)
   - Emits an overall similarity score (0–100%) paired with explainable factor breakdowns.
5. **Recurrence Detection (`recurrence.py`):**
   - Identifies returning sources after extended dormancy intervals (> 24 hours), recording duration, reactivation session, and behavioral pattern similarity.
6. **Prioritization Engine (`prioritization.py`):**
   - Categorizes profiles into `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INSUFFICIENT_DATA`.
   - Generates an immutable, transparent `priority_rationale` string.

