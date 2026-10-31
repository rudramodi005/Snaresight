# SnareSight: Configuration & Environment Strategy
**Document ID:** ARCH-009  
**Status:** Approved Configuration Baseline  

---

## 1. Principles of Configuration

1. **The Twelve-Factor App Methodology:** All configuration that varies across deployment targets (development, testing, isolated lab) is stored in environment variables, never hardcoded in source files.
2. **Strict Secret Management:**
   * Secret keys (JWT signing secret, decoy ingestion tokens, database passwords) must **never** be checked into version control.
   * A comprehensive `.env.example` file with dummy values documents all supported environment variables.
3. **Environment Separation:**
   * **Local Development (`.env.development`):** Localhost bindings (`127.0.0.1`), debug logging enabled, CORS relaxed for `localhost:5173`.
   * **Testing (`.env.test`):** In-memory or temporary database (`sqlite+aiosqlite:///` or test PostgreSQL instance), synthetic event injection enabled.
   * **Isolated Honeypot Lab (`.env.lab`):** Internal virtual subnet bindings (`172.28.0.0/16`), strict TLS token authentication, telemetry shipping enabled.

---

## 2. Configuration Schema (Conceptual Pydantic Model)

```python
class Settings(BaseSettings):
    # Application Info
    PROJECT_NAME: str = "SnareSight"
    ENVIRONMENT: str = "development"  # development | testing | production
    DEBUG: bool = False
    API_V1_STR: str = "/api/v1"
    
    # Security & Tokens
    SECRET_KEY: str  # Generated 256-bit secret for JWT signing
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480  # 8 hours
    DECOY_INGESTION_TOKEN: str  # Shared bearer secret between forwarder and collector
    
    # Database
    POSTGRES_SERVER: str = "127.0.0.1"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "snaresight"
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str = "snaresight_db"
    
    # CORS
    CORS_ORIGINS: list[str] = ["http://127.0.0.1:5173", "http://localhost:5173"]
    
    # Honeypot Decoy Lab
    DECOY_INTERNAL_SUBNET: str = "172.28.0.0/16"
    MAX_INGESTION_PAYLOAD_BYTES: int = 65536  # 64 KB
    
    # Intelligence
    MITRE_ATTACK_VERSION: str = "v15.1"
    
    class Config:
        env_file = ".env"
        case_sensitive = True
```

---

## 3. Example Sanitized Template (`.env.example`)

```ini
# ==============================================================================
# SNARESIGHT ENVIRONMENT CONFIGURATION TEMPLATE
# DO NOT COMMIT THE REAL .env FILE WITH ACTUAL SECRETS TO VERSION CONTROL
# ==============================================================================

ENVIRONMENT=development
DEBUG=True

# Security (Generate with: python -c "import secrets; print(secrets.token_hex(32))")
SECRET_KEY=replace_with_secure_random_hex_token_for_jwt_signing
DECOY_INGESTION_TOKEN=replace_with_secure_random_hex_token_for_telemetry

# Database Configuration (PostgreSQL)
POSTGRES_SERVER=127.0.0.1
POSTGRES_PORT=5432
POSTGRES_USER=snaresight_user
POSTGRES_PASSWORD=replace_with_secure_database_password
POSTGRES_DB=snaresight_soc

# Logging & Retention
LOG_LEVEL=INFO
EVENT_RETENTION_DAYS=90
```

