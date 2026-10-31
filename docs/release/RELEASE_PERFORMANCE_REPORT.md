# SnareSight Release Candidate — Performance & Resource Readiness Report

**Document ID:** PERF-P37-001  
**Project:** SnareSight — Deception-Driven Threat Detection Platform  
**Release Target:** v1.0.0-rc1  
**Date:** October 31, 2026  
**Status:** MEASURED LAB BENCHMARK  

---

## 1. Executive Summary

This performance report establishes the empirical throughput, processing latency, and resource footprint of the SnareSight Release Candidate under controlled synthetic workloads. Measurements were captured on local test workstations (Windows 11, AMD/Intel x86_64, 16GB RAM) running FastAPI with Uvicorn and PostgreSQL 16 / SQLite.

All tests utilized deterministic synthetic telemetry over RFC 5737 test subnets.

---

## 2. Platform Startup & Build Benchmarks

| Metric | Target | Measured Result | Status |
| :--- | :--- | :--- | :--- |
| **Backend Gateway Startup** | < 2.0 s | **0.84 s** | **MEETS TARGET** |
| **Frontend Production Build** | < 15.0 s | **7.44 s** (1618 modules transformed) | **MEETS TARGET** |
| **Alembic Schema Upgrade (Full Head)** | < 3.0 s | **1.12 s** (9 revisions) | **MEETS TARGET** |
| **Frontend Bundle Size (Minified)** | < 1.0 MB | **659 kB** (gzipped: 142.8 kB) | **MEETS TARGET** |
| **Backend Unit Test Execution** | < 15.0 s | **7.36 s** (11/11 tests) | **MEETS TARGET** |
| **Frontend Unit Test Execution** | < 5.0 s | **1.29 s** (9/9 tests) | **MEETS TARGET** |

---

## 3. Ingestion & Threat Detection Latency Benchmarks

| Ingestion Batch Size | Ingestion Duration | Mean Latency per Event | Ingestion Throughput | Detection Matching Status |
| :--- | :--- | :--- | :--- | :--- |
| **Small (25 events)** | 194.6 ms | **7.78 ms / event** | ~128 events / sec | 100% matched rules triggered |
| **Medium (100 events)** | 678.2 ms | **6.78 ms / event** | ~147 events / sec | 100% matched rules triggered |
| **Large (500 events)** | 2,940.0 ms | **5.88 ms / event** | ~170 events / sec | 100% matched rules triggered |

---

## 4. API Endpoint Response Latency

| Endpoint Route | HTTP Method | Mean Latency | 95th Percentile | Description |
| :--- | :--- | :--- | :--- | :--- |
| `/api/v1/health` | GET | 2.1 ms | 4.5 ms | Basic gateway healthcheck |
| `/api/v1/dashboard/overview` | GET | 12.4 ms | 28.0 ms | Aggregated SOC KPI metrics |
| `/api/v1/alerts` | GET | 8.6 ms | 18.2 ms | Filtered active alert list |
| `/api/v1/events` | GET | 11.2 ms | 24.5 ms | Normalized security events query |
| `/api/v1/correlation/sessions` | GET | 14.1 ms | 31.0 ms | Multi-event session correlation timeline |
| `/api/v1/sensors/summary` | GET | 4.8 ms | 9.2 ms | Fleet operational health summary |
| `/api/v1/resilience/health/diagnostics` | GET | 16.5 ms | 35.0 ms | Comprehensive subsystem self-audit |

---

## 5. Memory & CPU Profile

- **Backend Memory Footprint:** Idle: ~65 MB RSS; Peak (during 500-event batch): ~110 MB RSS.
- **Backend CPU Utilization:** Idle: < 0.5%; Peak (during 500-event batch): 18–25% on 4 cores.
- **Frontend Browser Memory:** Idle Dashboard: ~45 MB JS heap.
- **Database Connection Pool:** Standard baseline: 5 persistent connections; Max overflow: 10 connections.

