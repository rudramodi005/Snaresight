# Command Discovery Detection Specification (`CMD-001`) [DEFERRED]

## 1. Objective and Deployment Status
`CMD-001` is designed to detect environment discovery commands submitted during interactive honeypot sessions (e.g., shell interactions via SSH or telnet).

### Status: DEFERRED
The current production deployment of SnareSight utilizes the `WEB-001` decoy (an HTTP web-login decoy). Because `WEB-001` does not provide an interactive shell interface, genuine command interaction telemetry is not currently produced by the deployed honeypot fleet.

In compliance with SnareSight architectural rules:
- Detections are **NOT** fabricated using fictitious telemetry.
- The rule is registered with `enabled = False` and status `DRAFT / DEFERRED`.
- Controlled test suites verify that if command telemetry is provided in future adapters (e.g. Cowrie integration), it will be classified correctly without executing captured commands.

---

## 2. Supported Command Categories (Future Scope)
When interactive shell telemetry becomes active, the following categories are defined:
- `sys_info`: `uname`, `hostname`, `arch`, `cat /proc/version`
- `identity`: `whoami`, `id`, `w`, `last`
- `dir_listing`: `ls`, `dir`, `pwd`
- `network_recon`: `ifconfig`, `ip a`, `netstat`, `route`

---

## 3. Strict Safety Invariants
- Captured command text is treated as untrusted text strings only.
- SnareSight **NEVER** executes, pipes, evaluates, or passes recorded commands to system shells (`bash`, `cmd.exe`, `powershell`).

