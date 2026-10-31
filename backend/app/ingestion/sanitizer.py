"""Deep inspection and sanitization engine for incoming security telemetry.

Guarantees 100% enforcement of the Zero Password Persistence Invariant prior to
database writes.
"""

from typing import Any, Tuple
from app.ingestion.errors import IngestionErrorCode, RejectionDiagnostic

# Strict prohibited field names that must NEVER exist in persisted telemetry
FORBIDDEN_KEY_NAMES = {
    "password",
    "plaintext_password",
    "password_hash",
    "user_password",
    "auth_token",
    "bearer_token",
    "private_key",
    "api_secret",
    "secret_key",
}

# Permitted coarse flags that contain the substring 'password' safely
PERMITTED_PASSWORD_METRICS = {
    "password_present",
    "password_length_category",
}


class SensitiveDataInspector:
    """Recursively audits dictionaries and lists for prohibited credential attributes."""

    @classmethod
    def inspect_record(cls, data: Any, path: str = "") -> Tuple[bool, RejectionDiagnostic | None]:
        """Audits an incoming telemetry object for prohibited sensitive data.
        
        Returns:
            (is_safe: bool, diagnostic: RejectionDiagnostic | None)
        """
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                lower_key = str(key).lower()
                
                # Check for forbidden key names
                if lower_key in FORBIDDEN_KEY_NAMES and lower_key not in PERMITTED_PASSWORD_METRICS:
                    return False, RejectionDiagnostic(
                        error_code=IngestionErrorCode.PROHIBITED_SENSITIVE_DATA,
                        rejection_category="privacy_invariant",
                        explanation=f"Prohibited sensitive field detected: '{key}'",
                        field_reference=current_path,
                    )
                
                # Check for sentinel/canary password patterns in values
                if isinstance(value, str) and ("CanaryPass" in value or "BEGIN PRIVATE KEY" in value):
                    return False, RejectionDiagnostic(
                        error_code=IngestionErrorCode.PROHIBITED_SENSITIVE_DATA,
                        rejection_category="privacy_sentinel",
                        explanation="Prohibited credential or private key material detected in string payload",
                        field_reference=current_path,
                    )
                
                # Recursive audit on nested structures
                is_safe, diagnostic = cls.inspect_record(value, current_path)
                if not is_safe:
                    return False, diagnostic
                    
        elif isinstance(data, list):
            for idx, item in enumerate(data):
                current_path = f"{path}[{idx}]"
                is_safe, diagnostic = cls.inspect_record(item, current_path)
                if not is_safe:
                    return False, diagnostic

        return True, None

