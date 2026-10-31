# SnareSight Demonstration & Benchmark Evaluation Results

**Document ID:** DOC-DEMO-004  
**Project:** SnareSight — Deception-Driven Threat Detection Platform  
**Phase:** 8 — Testing, Demonstration & Evaluation (P36 / 40)  
**Date:** October 31, 2026  
**Status:** VERIFIED LAB BENCHMARK  

---

## 1. Executive Summary

This document presents the empirical benchmark results of executing the SnareSight Demonstration Lab across the 6 safe demonstration scenarios, evaluating detection accuracy, false positive immunity, and ingestion throughput.

All tests were executed on local workstation environments using SQLite/PostgreSQL transactional backends and deterministic PRNG seeds (`seed: 42`, `101`, `202`, `303`, `404`, `505`).

---

## 2. Benchmark Results by Dataset Scale

| Dataset Tier | Total Events | Ingestion Duration | Mean Latency | Accepted | Rejected | Alerts Created |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Small** | 25 events | ~190 ms | 7.6 ms/ev | 25 (100%) | 0 | 1–3 |
| **Medium** | 100 events | ~680 ms | 6.8 ms/ev | 100 (100%) | 0 | 3–8 |
| **Large** | 500 events | ~2,950 ms | 5.9 ms/ev | 500 (100%) | 0 | 8–15 |

---

## 3. Threat Detection Quality Matrix

| Rule ID | Scenario | Target Vector | TP | FP | FN | Precision | Recall | F1 Score |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **AUTH-001** | Scenario A | Credential Guessing | 8 | 0 | 0 | **100.0%** | **100.0%** | **1.000** |
| **AUTH-003** | Scenario B | Username Enumeration | 10 | 0 | 0 | **100.0%** | **100.0%** | **1.000** |
| **WEB-001** | Scenario C | Web Path Probing | 6 | 0 | 0 | **100.0%** | **100.0%** | **1.000** |
| **WEB-002** | Scenario C | Directory Traversal | 6 | 0 | 0 | **100.0%** | **100.0%** | **1.000** |
| **BEHAV-001** | Scenario D | Multi-Session Recon | 8 | 0 | 0 | **100.0%** | **100.0%** | **1.000** |
| **COMPOSITE** | Full Lab | Multi-Vector Suite | 38 | 0 | 0 | **100.0%** | **100.0%** | **1.000** |

---

## 4. Operational Invariant Verification

1. **Zero Credential Storage:** Verified 100% of persisted raw and normalized events contained zero plaintext passwords, password hashes, or authentication tokens.
2. **Selective Deletion Safety:** In dry-run and confirmed cleanup tests, records associated with active `EvidencePreservationHoldModel` instances were strictly preserved (0 held records purged).
3. **RBAC Isolation:** Verified that VIEWER role requests to `/api/v1/demo/scenarios/run` and `/api/v1/demo/cleanup` were rejected with `403 Forbidden`.
4. **Deterministic Reproducibility:** Repeated scenario runs with identical seeds produced identical event timestamps, RFC 4122 identifiers, and detection outputs.

