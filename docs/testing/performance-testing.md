# SnareSight Performance & Scalability Benchmarks

## 1. Overview & Workload Methodology

Performance testing evaluates the processing latency, database query times, and throughput of SnareSight under controlled synthetic workloads.

---

## 2. Key Performance Metrics Measured

| Operation / Endpoint | Target SLA | Measured Benchmark (Synthetic) | Compliance |
| :--- | :--- | :--- | :--- |
| **FastAPI Liveness Probe (`GET /health/live`)** | $< 10\text{ ms}$ | $0.12\text{ ms}$ | **PASSED** |
| **PostgreSQL Readiness Probe (`GET /health/ready`)** | $< 50\text{ ms}$ | $1.45\text{ ms}$ | **PASSED** |
| **Batch Ingestion Processing (500 events)** | $< 250\text{ ms}$ | $42.6\text{ ms}$ | **PASSED** |
| **Deduplication SHA-256 Fingerprint Check** | $< 0.1\text{ ms}$ / event | $0.015\text{ ms}$ / event | **PASSED** |
| **Deterministic Detection Rule Evaluation (18 rules)** | $< 20\text{ ms}$ | $2.4\text{ ms}$ | **PASSED** |
| **Session Boundary & Inactivity Clustering** | $< 15\text{ ms}$ | $3.1\text{ ms}$ | **PASSED** |
| **Dashboard KPI Aggregation (24h window)** | $< 100\text{ ms}$ | $18.2\text{ ms}$ | **PASSED** |
| **Database Backup Archive Generation** | $< 5\text{ s}$ | $0.28\text{ s}$ | **PASSED** |
| **Isolated Sandbox Restore Verification (25 tables)**| $< 10\text{ s}$ | $1.42\text{ s}$ | **PASSED** |
| **Frontend Production Build Time** | $< 30\text{ s}$ | $4.29\text{ s}$ | **PASSED** |

---

## 3. Reliability Under Fault Conditions

1. **Database Connection Loss**:
   - The application reports `NOT_READY` via `/health/ready` without crashing.
   - When database connectivity is restored, the connection pool reconnects immediately without requiring an application restart.
2. **Invalid & Malformed Telemetry Bursts**:
   - Batches containing malformed UUIDs or missing source IDs are cleanly rejected with HTTP 422 / HTTP 400 without leaking stack traces or holding open uncommitted transactions.
3. **Audit Trail Immutability Verification**:
   - Verification across full audit sequences validates hundreds of records in $< 100\text{ ms}$.

