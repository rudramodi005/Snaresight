# SnareSight: Cowrie SSH/Telnet Decoy Sensor Integration

## 1. Overview
The **CowrieDecoyAdapter** (`backend/app/ingestion/adapters/cowrie.py`) provides seamless ingestion and normalization of SSH and Telnet adversary interaction events captured on emulated Linux honeypot terminals.

## 2. Security & Zero-Password Sanitization
In strict adherence to the SnareSight Security Boundary Policy:
- Cleartext credentials attempted during SSH authentication are intercepted by the ingestion adapter.
- `password_present: true/false` boolean flags are preserved for brute-force rate calculations.
- Cleartext passwords are scrubbed before persistence or event emission, preventing credential leakage in SOC logs and telemetry exports.

## 3. Supported Event Types
- `cowrie.login.failed`: Brute-force and dictionary authentication attempts.
- `cowrie.login.success`: Emulated honeypot penetration / fake shell establishment.
- `cowrie.command.input`: Adversary terminal commands (e.g. `uname -a`, `curl -O`, `id`).
- `cowrie.session.connect` / `cowrie.session.closed`: Session connection lifecycle tracking.

## 4. Architectural Relationship to CMD-001
This adapter establishes the data contract foundation for future implementation of rule `CMD-001` (Command Execution on Emulated Terminals), currently documented as deferred in the Post-P40 Audit Report.
