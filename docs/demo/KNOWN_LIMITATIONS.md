# SnareSight Demonstration Lab — Known Limitations

**Document ID:** DOC-DEMO-005  
**Project:** SnareSight — Deception-Driven Threat Detection Platform  
**Phase:** 8 — Testing, Demonstration & Evaluation (P36 / 40)  
**Date:** October 31, 2026  
**Status:** ACTIVE RECORD  

---

## 1. Scope & Operational Limitations

This document explicitly outlines the technical, architectural, and analytical boundaries of the SnareSight Demonstration Lab.

### 1. Synthetic Emulation Only
All demonstration telemetry is generated using controlled pseudo-random algorithms and RFC 5737 test subnets. It does not represent live adversarial traffic, zero-day exploit payloads, or production network behavior.

### 2. IP Correlation Does Not Prove Personal Identity
Cross-session correlation and source IP profiling identify behavioral consistency between observation windows. In accordance with defensive security standards, IP correlation must never be claimed or interpreted as legal proof of individual personal identity (due to NAT gateways, proxy rotators, DHCP leasing, and shared networks).

### 3. Interactive Shell & File Transfer Honeypots Deferred
Detection rules `CMD-001` (Command Discovery Interaction) and `FILE-001` (File Transfer Probing) remain in `DRAFT` status and are disabled by default. The current demonstration environment operates against HTTP/Web login decoys (`WEB-001`). Interactive SSH containers (Cowrie) and file payload capture adapters are planned for subsequent phases.

### 4. Maximum Ingestion Batch Limit
The ingestion API enforces a hard ceiling of 500 events per submission batch (`POST /api/v1/ingestion/events/batch`). The demonstration runner automatically partitions large dataset requests into chunks of 200 events to respect this invariant.

### 5. Memory vs. Persistent Database In Benchmarks
In unit test execution, SQLite in-memory databases (`sqlite:///:memory:`) are utilized to guarantee test isolation. In full deployment mode, PostgreSQL 15+ is required to leverage native JSONB indexing and concurrency locking.

