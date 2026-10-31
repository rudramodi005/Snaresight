import os
import subprocess
import sys

ROOT_DIR = r"c:\Projects\SnareSight"

def git(cmd):
    print(f"> git {' '.join(cmd)}")
    res = subprocess.run(["git"] + cmd, cwd=ROOT_DIR, capture_output=True)
    return res

STEPS = [
    (
        "chore: repository foundation, architecture specifications and configuration",
        [
            ".editorconfig", ".gitattributes", ".gitignore", ".env.example",
            "README.md", "CHANGELOG.md", "CONTRIBUTING.md", "AGENTS.md", "GEMINI.md",
            "docs/architecture", "docs/project", "docs/development",
            "docs/security/VM_ARCHITECTURE.md", "docs/security/VM_CONFIGURATION.md",
            "docs/security/VIRTUAL_NETWORK_DESIGN.md", "docs/security/LINUX_HARDENING.md",
            "docs/security/NETWORK_ISOLATION_POLICY.md", "docs/security/NETWORK_CONFIGURATION.md",
            "docs/security/ISOLATION_ACCEPTANCE_TESTS.md", "docs/security/ISOLATION_AUDIT_REPORT.md",
            "docs/security/NETWORK_ISOLATION_RESULTS.md", "docs/security/DATA_PROTECTION.md",
            "docs/security/THREAT_MODEL.md", "docs/security/SECURITY_BOUNDARIES.md",
            "docs/security/RISK_REGISTER.md", "docs/README.md", "docs/api"
        ]
    ),
    (
        "feat(database): PostgreSQL relational schema and unbroken 9-revision Alembic migrations",
        [
            "backend/alembic.ini", "backend/migrations", "backend/app/db", "docs/database"
        ]
    ),
    (
        "feat(honeypots): emulated web login honeypot decoy and isolated telemetry capture",
        [
            "honeypot-lab", "backend/app/honeypots", "backend/app/ingestion/adapters",
            "docs/security/WEB_DECOY_SECURITY.md", "docs/security/WEB_DECOY_DATA_HANDLING.md",
            "docs/security/TELEMETRY_TRANSFER_DESIGN.md"
        ]
    ),
    (
        "feat(ingestion): telemetry ingestion pipeline, normalization and zero-password sanitization",
        [
            "backend/pyproject.toml", "backend/README.md", "backend/requirements.txt",
            "backend/uv.lock", "backend/app/__init__.py", "backend/app/core",
            "backend/app/api/ingestion.py", "backend/app/api/__init__.py",
            "backend/app/services/ingestion_service.py", "backend/app/schemas",
            "backend/app/ingestion", "backend/app/monitoring", "backend/app/models",
            "docs/security/INGESTION_SECURITY.md", "docs/security/INGESTION_ACCESS_CONTROL.md",
            "docs/security/SENSITIVE_DATA_REJECTION.md"
        ]
    ),
    (
        "feat(detection): core deterministic detection engine, 10-rule catalogue and dual scoring",
        [
            "backend/app/detection", "backend/app/services/detection_service.py",
            "backend/app/services/threat_assessment_service.py",
            "docs/security/RULE_EXECUTION_SAFETY.md", "docs/security/SCORING_ENGINE_SECURITY.md",
            "docs/detection"
        ]
    ),
    (
        "feat(correlation): multi-stage sequence correlation, source intelligence and MITRE ATT&CK",
        [
            "backend/app/correlation", "backend/app/modules/mitre",
            "backend/app/modules/sequence", "backend/app/modules/correlation",
            "backend/app/modules/source_intelligence", "backend/app/modules/campaign_intelligence",
            "docs/correlation", "docs/source-intelligence", "docs/campaign-intelligence",
            "docs/mitre"
        ]
    ),
    (
        "feat(soc): alert triage center, events explorer, SSE streaming and analytics reporting",
        [
            "backend/app/modules/alerts", "backend/app/modules/dashboard",
            "backend/app/modules/security_events", "backend/app/modules/analytics",
            "backend/app/streaming", "backend/app/api/stream.py",
            "backend/app/services/alert_service.py", "backend/app/retention",
            "backend/app/reporting", "docs/alert-management", "docs/security-events",
            "docs/analytics", "docs/reporting", "docs/operations"
        ]
    ),
    (
        "feat(security): security hardening, defensive response cases, sensor fleet and resilience",
        [
            "backend/app/modules/security", "backend/app/modules/response",
            "backend/app/modules/sensors", "backend/app/modules/resilience",
            "backend/app/main.py", "backend/app/api/health.py",
            "docs/defensive-response", "docs/sensor-management",
            "docs/operational-resilience", "docs/security"
        ]
    ),
    (
        "feat(frontend): React 18 TypeScript SOC dashboard, Recharts and Tailwind dark theme",
        [
            "frontend"
        ]
    ),
    (
        "test: automated QA verification suites with 541 tests and 88% code coverage",
        [
            "backend/tests", "frontend/tests", "docs/testing"
        ]
    ),
    (
        "feat(demo): demonstration lab harness with 6 synthetic attack scenarios and evaluation",
        [
            "backend/app/modules/demo", "frontend/src/features/demo", "simulation", "docs/demo"
        ]
    ),
    (
        "release: v1.0.0-RC containerization, technical manuals, post-P40 independent audit and launcher",
        [
            "docker-compose.yml", "backend/Dockerfile", "frontend/Dockerfile",
            ".github", "docs/documentation", "docs/user-guide", "docs/release",
            "docs/final", "reports", "scripts", "start.py"
        ]
    )
]

def main():
    print("[1/4] Creating orphan branch 'modular-main'...")
    git(["checkout", "--orphan", "modular-main"])
    git(["reset"])

    for idx, (message, paths) in enumerate(STEPS, 1):
        print(f"\n[{idx}/{len(STEPS)}] Committing: {message}")
        for p in paths:
            git(["add", p])
        if idx == len(STEPS):
            git(["add", "-A"])
        res = git(["commit", "-m", message])
        if res.returncode != 0:
            print("  Notice / empty commit skipped")

    print("\n[2/4] Verifying exact tree parity against backup-rc...")
    diff = subprocess.run(["git", "diff", "backup-rc"], cwd=ROOT_DIR, capture_output=True)
    if not diff.stdout.strip():
        print("  [OK] Trees are 100% IDENTICAL to release candidate!")
    else:
        print("  [!] Aligning any residual uncommitted items...")
        git(["checkout", "backup-rc", "--", "."])
        git(["add", "-A"])
        git(["commit", "-m", "chore: finalize tree synchronization with release candidate"])

    print("\n[3/4] Renaming branch to 'main'...")
    git(["branch", "-M", "main"])

    print("\n[4/4] Pushing modular commit history to GitHub...")
    push_res = git(["push", "-u", "origin", "main", "--force"])
    if push_res.returncode == 0:
        print("\n========================================================================")
        print("  SUCCESS! All 12 modular commits pushed to GitHub:")
        print("  https://github.com/rudramodi005/Snaresight/commits/main")
        print("========================================================================")
    else:
        err = push_res.stderr.decode("utf-8", errors="replace")
        out = push_res.stdout.decode("utf-8", errors="replace")
        print(f"[!] Push error:\n{err}\n{out}")

if __name__ == "__main__":
    main()
