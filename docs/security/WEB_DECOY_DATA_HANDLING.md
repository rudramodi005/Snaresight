# SnareSight: Web Decoy Sensitive Data Handling Policy
**Document ID:** SEC-DEC-002  
**Phase:** 2 — Lab Isolation and Honeypot  
**Status:** Approved Data Privacy Specification  

---

## 1. Zero-Password Persistence Invariant

* **The Problem:** Attackers frequently enter actual personal passwords, leaked corporate credentials, or dictionary passphrases into honeypot forms.
* **The Invariant:** **SnareSight strictly prohibits storing submitted passwords in any form (plaintext, hashed, or encrypted).**
* **Enforcement:**
  1. Password parameter enters memory only during the active HTTP request scope.
  2. Length is evaluated and mapped to a coarse category: `none`, `short (<8)`, `medium (8-16)`, or `long (>16)`.
  3. The variable is immediately dereferenced via `del password`.
  4. Pre-write assertion in `DecoyEventLogger` rejects serialization if any `"password":` key is detected.

---

## 2. Keyed HMAC-SHA256 Username Pseudonymization

* Rather than storing corporate email addresses or usernames in raw text, the decoy computes:
  $$\text{HMAC-SHA256}(\text{Salt}, \text{Normalized Username})[0:16]$$
* **Result:** Generates an irreversible, deterministic 16-character hex pseudonym (e.g. `8b23f051e941a8bc`).
* **Analytical Benefit:** Allows the detection engine to identify credential stuffing (same IP trying 100 different usernames) or targeted password spraying (same username tried across multiple hours) without retaining sensitive personal data.

