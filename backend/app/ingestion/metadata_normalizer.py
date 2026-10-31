"""Metadata normalization engine for SnareSight event telemetry.

Extracts, structures, and sanitizes interaction metadata (HTTP, Auth, Command, File)
while enforcing strict zero password persistence.
"""

from typing import Any, Dict


class MetadataNormalizer:
    """Standardizes heterogeneous interaction payloads into structured forensic categories."""

    PROHIBITED_METADATA_KEYS = {
        "password",
        "passwd",
        "auth_token",
        "authorization",
        "bearer_token",
        "jwt",
        "private_key",
        "secret_key",
        "api_secret",
        "credentials",
    }

    @classmethod
    def normalize_metadata(cls, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Structures and cleans interaction details into sanitized categories."""
        interaction = raw_event.get("interaction", {})
        request_data = raw_event.get("request", {})
        source_meta = raw_event.get("source", {})

        # 1. Authentication Interaction Metadata
        username = interaction.get("username_attempted") or interaction.get("username")
        auth_metadata = {
            "username_fingerprint": interaction.get("username_fingerprint") or (f"user_{len(username)}" if username else None),
            "username_length": interaction.get("username_length") or (len(username) if username else None),
            "password_present": bool(interaction.get("password_present", False) or "password" in interaction),
            "password_length_category": interaction.get("password_length_category", "NONE"),
            "simulated_outcome": interaction.get("simulated_outcome"),
        }

        # 2. HTTP Interaction Metadata
        status_code = interaction.get("status_code", 200)
        method = request_data.get("method") or interaction.get("method") or "GET"
        path = request_data.get("path") or interaction.get("path") or "/"
        user_agent = (
            source_meta.get("user_agent_summary")
            or raw_event.get("client", {}).get("user_agent")
            or "unknown"
        )
        http_metadata = {
            "method": method.upper(),
            "path": path,
            "status_code": status_code,
            "user_agent": user_agent,
        }

        # 3. Command / Shell Interaction Metadata (where supported)
        command_metadata = None
        if "command" in interaction:
            command_metadata = {
                "command_category": interaction.get("command_category", "EXPLORATION"),
                "sanitized_cmd": str(interaction.get("command"))[:256],
            }

        # 4. File Interaction Metadata (where supported)
        file_metadata = None
        if "file" in interaction:
            file_metadata = {
                "filename": str(interaction["file"].get("filename", "unknown"))[:128],
                "file_size": interaction["file"].get("size", 0),
            }

        sanitized_details: Dict[str, Any] = {
            "auth": auth_metadata,
            "http": http_metadata,
        }
        if command_metadata:
            sanitized_details["command"] = command_metadata
        if file_metadata:
            sanitized_details["file"] = file_metadata

        # 5. Extra permitted fields (preserving source forensic evidence)
        if "headers" in interaction and isinstance(interaction["headers"], dict):
            # Safe headers excluding authorization / cookies
            safe_headers = {
                k: v for k, v in interaction["headers"].items()
                if k.lower() not in {"authorization", "cookie", "set-cookie", "x-api-key"}
            }
            sanitized_details["safe_headers"] = safe_headers

        return sanitized_details

