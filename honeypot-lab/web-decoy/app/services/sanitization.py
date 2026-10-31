"""Sanitization and sensitive data protection utilities.

Implements strict zero-password persistence invariants and privacy-preserving
keyed HMAC pseudonymization for observed usernames.
"""

import hashlib
import hmac
import html
import re
from typing import Optional


def sanitize_string(val: Optional[str], max_len: int = 256) -> str:
    """Sanitizes untrusted string input by escaping HTML and stripping control characters."""
    if not val:
        return ""
    # Strip non-printable / control characters
    cleaned = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", val)
    # Truncate to maximum permitted length
    truncated = cleaned[:max_len]
    # Escape HTML entities so log contents remain inert
    return html.escape(truncated)


def compute_username_fingerprint(username: Optional[str], salt_key: str) -> Optional[str]:
    """Generates a deterministic, irreversible HMAC-SHA256 fingerprint for a username.

    Prevents storing raw corporate usernames or email addresses while allowing
    analysts to correlate repeated credential stuffing attempts.
    """
    if not username:
        return None
    normalized = username.strip().lower()
    return hmac.new(
        salt_key.encode("utf-8"),
        normalized.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()[:16]


def categorize_password_length(password: Optional[str]) -> tuple[bool, Optional[str]]:
    """Analyzes submitted password presence and length category, then discards plaintext.

    INVARIANT: The plaintext password is NEVER returned or stored.
    Returns:
        (password_present, length_category)
    """
    if not password:
        return False, "none"

    length = len(password)
    if length < 8:
        category = "short (<8)"
    elif length <= 16:
        category = "medium (8-16)"
    else:
        category = "long (>16)"

    return True, category


def detect_payload_markers(text: str) -> list[str]:
    """Detects inert suspicious patterns (SQL, script tags, traversal) for forensic tagging.

    Does NOT execute or evaluate the content.
    """
    markers = []
    lower = text.lower()
    if "<script" in lower or "javascript:" in lower:
        markers.append("xss_marker")
    if "union select" in lower or "1=1" in lower or "' or '" in lower:
        markers.append("sqli_marker")
    if "../" in text or "..\\" in text:
        markers.append("traversal_marker")
    if ";" in text or "|" in text or "`" in text or "$(" in text:
        markers.append("command_injection_marker")
    return markers

