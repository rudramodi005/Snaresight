"""Exceptions for the SnareSight real-time event streaming subsystem."""


class StreamingError(Exception):
    """Base exception for streaming operations."""
    pass


class StreamAuthenticationError(StreamingError):
    """Raised when stream client fails authentication."""
    pass


class StreamAuthorizationError(StreamingError):
    """Raised when client is unauthorized for a requested stream or filter."""
    pass


class StreamCursorError(StreamingError):
    """Raised when client supplies an invalid, malformed, or expired cursor."""
    pass


class StreamQueueFullError(StreamingError):
    """Raised when a subscriber's bounded queue is full (slow client)."""
    pass


class StreamClientDisconnectedError(StreamingError):
    """Raised when a client disconnects unexpectedly."""
    pass


class StreamResourceLimitExceeded(StreamingError):
    """Raised when max concurrent connections or per-user limits are exceeded."""
    pass

