"""Custom exception classes for SnareSight Event Correlation Subsystem (Task P21)."""


class CorrelationError(Exception):
    """Base exception for correlation and session lifecycle failures."""

    def __init__(self, message: str, session_id: str | None = None):
        super().__init__(message)
        self.message = message
        self.session_id = session_id


class SessionNotFoundError(CorrelationError):
    """Raised when an activity session cannot be resolved by its identifier."""
    pass


class CorrelationPolicyError(CorrelationError):
    """Raised when a correlation policy configuration or boundary check fails."""
    pass


class InvalidSessionStateError(CorrelationError):
    """Raised when an illegal session state transition is attempted."""
    pass


class DuplicateAssociationError(CorrelationError):
    """Raised when an event is attempted to be bound multiple times inconsistently."""
    pass

