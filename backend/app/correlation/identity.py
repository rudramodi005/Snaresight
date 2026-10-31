"""Layered Session Identity Resolution Engine (Task P21)."""

from typing import Any, Dict, Optional, Tuple
from app.correlation.schemas import CorrelationMethod


class SessionIdentity:
    """Resolved identity context for correlation matching."""

    def __init__(
        self,
        correlation_method: CorrelationMethod,
        correlation_key: str,
        decoy_id: str,
        honeypot_type: str,
        source_address: str,
        source_port: Optional[int],
        target_service: str,
        protocol: str,
        explicit_session_id: Optional[str] = None,
        connection_id: Optional[str] = None,
        is_trustworthy: bool = True,
        resolution_diagnostic: str = "Resolved successfully",
    ):
        self.correlation_method = correlation_method
        self.correlation_key = correlation_key
        self.decoy_id = decoy_id
        self.honeypot_type = honeypot_type
        self.source_address = source_address
        self.source_port = source_port
        self.target_service = target_service
        self.protocol = protocol
        self.explicit_session_id = explicit_session_id
        self.connection_id = connection_id
        self.is_trustworthy = is_trustworthy
        self.resolution_diagnostic = resolution_diagnostic


class SessionIdentityResolver:
    """Extracts and resolves structured correlation identity signals from normalized events."""

    GENERIC_SESSION_IDENTIFIERS = {"unknown", "none", "null", "undefined", "0", "-1", ""}

    @classmethod
    def resolve_identity(cls, event: Dict[str, Any]) -> SessionIdentity:
        """Resolves correlation identity using Level 1 to Level 4 precedence."""
        decoy_id = str(event.get("decoy_id") or "WEB-001")
        honeypot_type = "WEB_LOGIN" if decoy_id.startswith("WEB") else "SSH_DAEMON"
        source_address = str(event.get("source_address") or "0.0.0.0")
        source_port = event.get("source_port")
        target_service = str(event.get("target_service") or "HTTP")
        protocol = str(event.get("source_protocol") or "TCP")

        meta = event.get("sanitized_metadata") or event.get("metadata") or {}

        # ---------------------------------------------------------------------
        # LEVEL 1: Explicit Honeypot Session Identifier
        # ---------------------------------------------------------------------
        explicit_sess = str(event.get("session_id") or "").strip()
        if explicit_sess and explicit_sess.lower() not in cls.GENERIC_SESSION_IDENTIFIERS:
            # Compound Scoping: decoy_id + honeypot_type + explicit_session_id
            compound_key = f"{decoy_id}:{honeypot_type}:{explicit_sess}"
            return SessionIdentity(
                correlation_method=CorrelationMethod.EXPLICIT_SESSION_ID,
                correlation_key=compound_key,
                decoy_id=decoy_id,
                honeypot_type=honeypot_type,
                source_address=source_address,
                source_port=source_port,
                target_service=target_service,
                protocol=protocol,
                explicit_session_id=explicit_sess,
                is_trustworthy=True,
                resolution_diagnostic=f"Resolved via explicit honeypot session token '{explicit_sess}'",
            )

        # ---------------------------------------------------------------------
        # LEVEL 2: Explicit Connection Identifier
        # ---------------------------------------------------------------------
        conn_id = meta.get("connection_id") or meta.get("interaction_id")
        if conn_id and str(conn_id).strip().lower() not in cls.GENERIC_SESSION_IDENTIFIERS:
            conn_str = str(conn_id).strip()
            compound_key = f"{decoy_id}:conn:{conn_str}"
            return SessionIdentity(
                correlation_method=CorrelationMethod.EXPLICIT_CONNECTION_ID,
                correlation_key=compound_key,
                decoy_id=decoy_id,
                honeypot_type=honeypot_type,
                source_address=source_address,
                source_port=source_port,
                target_service=target_service,
                protocol=protocol,
                connection_id=conn_str,
                is_trustworthy=True,
                resolution_diagnostic=f"Resolved via explicit connection identifier '{conn_str}'",
            )

        # ---------------------------------------------------------------------
        # LEVEL 3: Controlled Fallback Correlation
        # ---------------------------------------------------------------------
        # Invariant: IP address alone is NEVER sufficient; scoped by decoy instance and target service
        if source_address and source_address != "0.0.0.0":
            fallback_key = f"fallback:{source_address}:{decoy_id}:{target_service}"
            return SessionIdentity(
                correlation_method=CorrelationMethod.CONTEXTUAL_FALLBACK,
                correlation_key=fallback_key,
                decoy_id=decoy_id,
                honeypot_type=honeypot_type,
                source_address=source_address,
                source_port=source_port,
                target_service=target_service,
                protocol=protocol,
                is_trustworthy=False,
                resolution_diagnostic="Resolved via contextual fallback key (source_address + decoy_id + target_service)",
            )

        # ---------------------------------------------------------------------
        # LEVEL 4: No Reliable Correlation (Standalone Observation)
        # ---------------------------------------------------------------------
        standalone_key = f"standalone:{event.get('event_id') or 'unknown'}"
        return SessionIdentity(
            correlation_method=CorrelationMethod.STANDALONE,
            correlation_key=standalone_key,
            decoy_id=decoy_id,
            honeypot_type=honeypot_type,
            source_address=source_address,
            source_port=source_port,
            target_service=target_service,
            protocol=protocol,
            is_trustworthy=False,
            resolution_diagnostic="Insufficient telemetry signals; isolated as standalone observation",
        )

