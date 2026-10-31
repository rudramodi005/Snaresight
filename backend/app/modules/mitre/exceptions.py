"""Domain-specific exceptions for SnareSight MITRE ATT&CK integration."""


class MitreError(Exception):
    """Base exception for all MITRE ATT&CK module errors."""

    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class MitreParsingError(MitreError):
    """Raised when STIX 2.1 parsing fails due to syntax or malformed structure."""
    pass


class MitreValidationError(MitreError):
    """Raised when ATT&CK objects fail structural, field, or ID validation."""
    pass


class MitreImportError(MitreError):
    """Raised when dry-run, persistence, or transactional import encounters a failure."""
    pass


class MitreVersionError(MitreError):
    """Raised when dataset release, active versioning, or rollback operations fail."""
    pass


class MitreNotFoundError(MitreError):
    """Raised when requested tactic, technique, or dataset version cannot be located."""
    pass


class MitreAuthorizationError(MitreError):
    """Raised when non-administrative actors attempt restricted import/rollback operations."""
    pass

