# SnareSight: Web-Login Decoy Service (`ApexCore Portal`)
**Service Name:** `snaresight-web-decoy`  
**Phase:** 2 — Lab Isolation and Honeypot  
**Status:** Implemented & 100% Tested (39 Automated Unit, Security, & Validation Tests Passing)  

---

## 1. Service Overview

The SnareSight Web-Login Decoy (`WEB-001`) is a lightweight, deceptive authentication portal designed to emulate an enterprise single sign-on (SSO) system (**"ApexCore Logistics Employee Access Portal"**).

It captures adversary interaction metadata, enforces strict privacy protections, generates canonical JSONL security events, and manages opaque session cookies—without ever connecting to a real authentication database, executing user input, or storing submitted passwords.

---

## 2. Technical Architecture

* **Framework:** Python 3.14 + FastAPI + Pydantic v2
* **Storage Engine:** Append-only JSONL format (`data/events.jsonl`) with thread locking and log rotation.
* **Templating:** Server-rendered Jinja2 templates (HTML5 + CSS3, zero external CDN scripts).
* **Network Binding:** Binds strictly to `127.0.0.1` by default; raises fatal configuration errors on wildcard `0.0.0.0` or `::`.
* **Testing:** Complete test suite with 39 automated security, session, schema, input boundary, concurrency, and log rotation tests.

---

## 3. Directory Layout

```
honeypot-lab/web-decoy/
├── app/
│   ├── config.py           # Pydantic configuration with wildcard binding prohibition
│   ├── main.py             # FastAPI entry point, security headers & 404 handlers
│   ├── routes/
│   │   ├── health.py       # Minimal /health endpoint (no leaked secrets)
│   │   └── login.py        # GET / (portal view), POST /login, GET /logout
│   ├── schemas/
│   │   └── events.py       # Pydantic schemas for DecoyEvent and EventInteraction
│   ├── services/
│   │   ├── event_logger.py # Thread-safe JSONL logger with password exclusion assertions
│   │   ├── sanitization.py # Keyed HMAC username fingerprinting & password length categorizer
│   │   └── session_manager.py # Opaque session tracker (decoy_sess_<uuid>)
│   ├── static/css/
│   │   └── style.css       # Dark enterprise cyber styling
│   └── templates/
│       ├── login.html      # Deceptive corporate authentication portal
│       └── simulated_portal.html # Read-only mock operational dispatch dashboard
├── data/
│   └── events.jsonl        # Output JSONL events (excluded from Git)
├── tests/
│   ├── test_events.py      # Schema conformity, UTC timestamps, write failure resilience
│   ├── test_login.py       # Page rendering, simulated rejections, 404 probing
│   ├── test_security.py    # XSS escaping, command injection inertness, no file uploads
│   ├── test_sessions.py    # Unique sessions & deterministic HMAC fingerprinting
│   └── test_validation_suite.py # INPUT-001 to INPUT-017, thread concurrency, log rotation
├── .env.example            # Sanitized environment template
├── pyproject.toml          # Service build manifest
└── README.md
```

---

## 4. Sensitive Data Protection Invariants

1. **Zero Password Persistence:**
   * Submitted passwords exist only in memory long enough to categorize length (`none`, `short (<8)`, `medium (8-16)`, `long (>16)`).
   * The password string is immediately dereferenced and garbage collected (`del password`).
   * A hardcoded assertion in `DecoyEventLogger` rejects any payload containing `"password":`.
2. **Keyed HMAC Username Pseudonymization:**
   * Usernames are transformed into irreversible 64-character HMAC-SHA256 hex digests using a local secret salt key, allowing brute-force pattern correlation without storing corporate identifiers.
3. **Inert Data Handling:**
   * Script tags (`<script>`), SQL syntax (`UNION SELECT`), and command characters (`;`, `|`) are treated strictly as inert string data and escaped.

---

## 5. Offline Startup & Verification

### Running Complete Automated Test Suite (39 Tests):
```powershell
cd c:\Projects\SnareSight\honeypot-lab\web-decoy
python -m unittest discover tests -v
```

### Starting the Service in Offline Development Mode (Loopback Only):
```powershell
cd c:\Projects\SnareSight\honeypot-lab\web-decoy
python app\main.py
# Listens on http://127.0.0.1:8080/
```

---

## 6. Verification Reports
Detailed QA, validation, and security audit reports are preserved in:
- `docs/testing/HONEYPOT_TEST_PLAN.md`
- `docs/testing/HONEYPOT_TEST_RESULTS.md`
- `docs/testing/EVENT_VALIDATION_REPORT.md`
- `docs/testing/SESSION_VALIDATION_REPORT.md`
- `docs/testing/DATA_PROTECTION_TESTS.md`
- `docs/testing/NETWORK_VALIDATION_RESULTS.md`
