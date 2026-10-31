"""Comprehensive automated security verification suite for SnareSight (Task P31).

Verifies authentication, bcrypt hashing, JWT lifecycle, rate-limiting, RBAC,
injection defense, request size bounding, audit logging, security headers,
SSE authorization, and telemetry isolation.
"""

import unittest
import uuid
import time
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.core.config import settings

from app.db.models.security import UserModel, RevokedTokenModel, SystemAuditLogModel
from app.modules.security.crypto import hash_password, verify_password, create_access_token
from app.modules.security.rate_limiter import auth_rate_limiter
from app.modules.security.permissions import Permission, Role, has_permission, ROLE_PERMISSIONS
from app.modules.security.dependencies import AuthenticatedUser, get_current_user


class TestSecurityHardeningSuite(unittest.TestCase):
    """Automated security hardening verification test suite."""

    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.TestingSessionLocal = sessionmaker(
            autocommit=False, autoflush=False, bind=self.engine
        )
        self.db = self.TestingSessionLocal()

        def override_get_db():
            try:
                yield self.db
            finally:
                pass

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

        # Create test users
        self.admin_user = UserModel(
            id=str(uuid.uuid4()),
            username="test_admin",
            email="admin@test.local",
            hashed_password=hash_password("ComplexAdminPass123!"),
            role="ADMIN",
            is_active=True,
        )
        self.analyst_user = UserModel(
            id=str(uuid.uuid4()),
            username="test_analyst",
            email="analyst@test.local",
            hashed_password=hash_password("ComplexAnalystPass123!"),
            role="ANALYST",
            is_active=True,
        )
        self.viewer_user = UserModel(
            id=str(uuid.uuid4()),
            username="test_viewer",
            email="viewer@test.local",
            hashed_password=hash_password("ComplexViewerPass123!"),
            role="VIEWER",
            is_active=True,
        )
        self.deactivated_user = UserModel(
            id=str(uuid.uuid4()),
            username="test_disabled",
            email="disabled@test.local",
            hashed_password=hash_password("DisabledPass123!"),
            role="ANALYST",
            is_active=False,
        )
        self.db.add_all([self.admin_user, self.analyst_user, self.viewer_user, self.deactivated_user])
        self.db.commit()

        # Reset rate limiter
        auth_rate_limiter._attempts.clear()

    def tearDown(self):
        app.dependency_overrides.clear()
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)

    def test_01_password_hashing_bcrypt(self):
        """TEST SEC-001: Verifies bcrypt salted password hashing and verification."""
        pwd = "UltraSecurePassword999!"
        h1 = hash_password(pwd)
        h2 = hash_password(pwd)

        # Salting guarantees distinct hash representations for identical passwords
        self.assertNotEqual(h1, h2)
        self.assertTrue(h1.startswith("$2b$12$"))
        self.assertTrue(verify_password(pwd, h1))
        self.assertTrue(verify_password(pwd, h2))
        self.assertFalse(verify_password("WrongPassword", h1))

    def test_02_plaintext_passwords_never_stored_or_leaked(self):
        """TEST SEC-002: Verifies password hashes are salted and UserResponse never leaks passwords."""
        token, _ = create_access_token({"sub": "test_admin", "user_id": self.admin_user.id, "role": "ADMIN"})
        headers = {"Authorization": f"Bearer {token}"}

        resp = self.client.get("/api/v1/auth/users", headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreater(len(data), 0)
        for user in data:
            self.assertNotIn("password", user)
            self.assertNotIn("hashed_password", user)

    def test_03_login_authentication_success(self):
        """TEST SEC-003: Verifies successful login returns token, permissions, and HttpOnly cookie."""
        resp = self.client.post(
            "/api/v1/auth/login",
            json={"username": "test_analyst", "password": "ComplexAnalystPass123!"},
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("access_token", body)
        self.assertEqual(body["role"], "ANALYST")
        self.assertIn("view_alerts", body["permissions"])
        self.assertIn("snaresight_session", resp.cookies)

    def test_04_login_failure_generic_error_no_enumeration(self):
        """TEST SEC-004: Verifies identical error messages for nonexistent user vs bad password."""
        # Non-existent user
        resp1 = self.client.post(
            "/api/v1/auth/login",
            json={"username": "non_existent_user_xyz", "password": "AnyPassword123!"},
        )
        self.assertEqual(resp1.status_code, 401)
        self.assertEqual(resp1.json()["detail"], "Invalid username or password")

        # Existing user with incorrect password
        resp2 = self.client.post(
            "/api/v1/auth/login",
            json={"username": "test_analyst", "password": "WrongPassword999!"},
        )
        self.assertEqual(resp2.status_code, 401)
        self.assertEqual(resp2.json()["detail"], "Invalid username or password")

    def test_05_login_rate_limiting(self):
        """TEST SEC-005: Verifies rate limiting locks out client after 5 consecutive failed logins."""
        for _ in range(5):
            r = self.client.post(
                "/api/v1/auth/login",
                json={"username": "test_analyst", "password": "WrongPassword!"},
            )
            self.assertEqual(r.status_code, 401)

        # 6th attempt must be rejected with 429 Too Many Requests
        r_locked = self.client.post(
            "/api/v1/auth/login",
            json={"username": "test_analyst", "password": "WrongPassword!"},
        )
        self.assertEqual(r_locked.status_code, 429)
        self.assertIn("Too many failed login attempts", r_locked.json()["detail"])

    def test_06_unauthenticated_request_rejection(self):
        """TEST SEC-006: Verifies unauthenticated requests to protected endpoints return 401 in ENFORCED mode."""
        old_mode = settings.AUTH_ENFORCEMENT_MODE
        try:
            settings.AUTH_ENFORCEMENT_MODE = "ENFORCED"
            # Access admin user endpoint with no token
            resp = self.client.get("/api/v1/auth/users")
            self.assertEqual(resp.status_code, 401)
        finally:
            settings.AUTH_ENFORCEMENT_MODE = old_mode

    def test_07_unauthorized_role_rejection(self):
        """TEST SEC-007: Verifies VIEWER role is forbidden from performing administrative actions (403)."""
        token, _ = create_access_token({"sub": "test_viewer", "user_id": self.viewer_user.id, "role": "VIEWER"})
        headers = {"Authorization": f"Bearer {token}"}

        resp = self.client.get("/api/v1/auth/users", headers=headers)
        self.assertEqual(resp.status_code, 403)
        self.assertIn("Insufficient privileges", resp.json()["detail"])

    def test_08_privilege_escalation_prevention(self):
        """TEST SEC-008: Verifies non-admin cannot create users or promote their own role."""
        token, _ = create_access_token({"sub": "test_analyst", "user_id": self.analyst_user.id, "role": "ANALYST"})
        headers = {"Authorization": f"Bearer {token}"}

        resp = self.client.post(
            "/api/v1/auth/users",
            json={
                "username": "rogue_admin",
                "email": "rogue@test.local",
                "password": "Password123!",
                "role": "ADMIN",
            },
            headers=headers,
        )
        self.assertEqual(resp.status_code, 403)

    def test_09_logout_session_invalidation(self):
        """TEST SEC-009: Verifies token JTI is revoked upon logout and rejected subsequently."""
        token, jti = create_access_token({"sub": "test_analyst", "user_id": self.analyst_user.id, "role": "ANALYST"})
        headers = {"Authorization": f"Bearer {token}"}

        # Successful call
        r1 = self.client.get("/api/v1/auth/me", headers=headers)
        self.assertEqual(r1.status_code, 200)

        # Logout
        r_logout = self.client.post("/api/v1/auth/logout", headers=headers)
        self.assertEqual(r_logout.status_code, 200)

        # Post-logout request with same token must fail with 401
        r2 = self.client.get("/api/v1/auth/me", headers=headers)
        self.assertEqual(r2.status_code, 401)
        self.assertIn("revoked", r2.json()["detail"])

    def test_10_token_expiration(self):
        """TEST SEC-010: Verifies expired JWT tokens are rejected with 401."""
        expired_token, _ = create_access_token(
            {"sub": "test_analyst", "user_id": self.analyst_user.id, "role": "ANALYST"},
            expires_delta=timedelta(seconds=-10),  # expired 10 seconds ago
        )
        headers = {"Authorization": f"Bearer {expired_token}"}
        resp = self.client.get("/api/v1/auth/me", headers=headers)
        self.assertEqual(resp.status_code, 401)
        self.assertIn("expired", resp.json()["detail"].lower())

    def test_11_sql_injection_resistance(self):
        """TEST SEC-011: Verifies SQL injection payloads in parameters do not execute or compromise data."""
        token, _ = create_access_token({"sub": "test_admin", "user_id": self.admin_user.id, "role": "ADMIN"})
        headers = {"Authorization": f"Bearer {token}"}

        malicious_input = "' OR '1'='1"
        resp = self.client.get(f"/api/v1/audit/logs?actor_username={malicious_input}", headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["total"], 0)

    def test_12_request_size_limits(self):
        """TEST SEC-012: Verifies oversized request body payload is rejected with 413."""
        # 3MB exceeds the 2MB general limit
        headers = {"Content-Length": str(3 * 1024 * 1024)}
        resp = self.client.post("/api/v1/auth/login", json={"username": "a", "password": "b"}, headers=headers)
        self.assertEqual(resp.status_code, 413)
        self.assertIn("Payload too large", resp.json()["detail"])

    def test_13_sensitive_field_redaction(self):
        """TEST SEC-013: Verifies password and secret fields in audit contexts are redacted."""
        from app.modules.security.audit_service import audit_service
        entry = audit_service.log_event(
            db=self.db,
            actor_username="test_admin",
            actor_role="ADMIN",
            action="TEST_ACTION",
            resource_type="SYSTEM",
            request_context={"password": "MySuperSecretPassword", "safe_field": "123"},
        )
        self.assertEqual(entry.request_context["password"], "[REDACTED]")
        self.assertEqual(entry.request_context["safe_field"], "123")

    def test_14_audit_logging_recorded(self):
        """TEST SEC-014: Verifies security actions write immutable records to system_audit_logs."""
        # Successful login generates audit log
        self.client.post(
            "/api/v1/auth/login",
            json={"username": "test_analyst", "password": "ComplexAnalystPass123!"},
        )
        log = self.db.query(SystemAuditLogModel).filter(
            SystemAuditLogModel.action == "LOGIN",
            SystemAuditLogModel.actor_username == "test_analyst"
        ).first()
        self.assertIsNotNone(log)
        self.assertEqual(log.outcome, "SUCCESS")

    def test_15_audit_log_access_restrictions(self):
        """TEST SEC-015: Verifies audit log querying requires view_audit_logs permission."""
        # VIEWER role has no view_audit_logs permission
        viewer_token, _ = create_access_token({"sub": "test_viewer", "user_id": self.viewer_user.id, "role": "VIEWER"})
        r_viewer = self.client.get("/api/v1/audit/logs", headers={"Authorization": f"Bearer {viewer_token}"})
        self.assertEqual(r_viewer.status_code, 403)

        # ANALYST role has view_audit_logs permission
        analyst_token, _ = create_access_token({"sub": "test_analyst", "user_id": self.analyst_user.id, "role": "ANALYST"})
        r_analyst = self.client.get("/api/v1/audit/logs", headers={"Authorization": f"Bearer {analyst_token}"})
        self.assertEqual(r_analyst.status_code, 200)

    def test_16_security_headers_present(self):
        """TEST SEC-016: Verifies security headers are appended to all HTTP responses."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(resp.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")
        self.assertIn("default-src 'self'", resp.headers.get("Content-Security-Policy", ""))

    def test_17_cors_restrictions(self):
        """TEST SEC-017: Verifies unauthorized origins do not receive permissive Access-Control-Allow-Origin."""
        resp = self.client.get("/", headers={"Origin": "http://malicious-attacker.com"})
        self.assertNotEqual(resp.headers.get("Access-Control-Allow-Origin"), "http://malicious-attacker.com")

    def test_18_sse_authentication(self):
        """TEST SEC-018: Verifies SSE stream authenticates via valid JWT and rejects invalid token."""
        # Valid JWT
        token, _ = create_access_token({"sub": "test_analyst", "user_id": self.analyst_user.id, "role": "ANALYST"})
        headers = {"Authorization": f"Bearer {token}"}
        resp = self.client.get("/api/v1/stream/events?limit=1", headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("content-type"), "text/event-stream; charset=utf-8")

        # Invalid token
        bad_headers = {"Authorization": "Bearer completely_bogus_token_xyz"}
        resp_bad = self.client.get("/api/v1/stream/events?limit=1", headers=bad_headers)
        self.assertEqual(resp_bad.status_code, 401)

    def test_19_telemetry_isolation_and_auth(self):
        """TEST SEC-019: Verifies ingestion gateway rejects telemetry lacking valid X-API-Key."""
        # Missing X-API-Key
        r1 = self.client.post("/api/v1/ingestion/events/batch", json={"events": []})
        self.assertEqual(r1.status_code, 401)

        # Invalid X-API-Key
        r2 = self.client.post(
            "/api/v1/ingestion/events/batch",
            json={"events": []},
            headers={"X-API-Key": "invalid_collector_key"},
        )
        self.assertEqual(r2.status_code, 401)

    def test_20_query_param_token_rejection(self):
        """TEST SEC-020: Verifies passing credentials in query parameters is strictly rejected (400)."""
        resp = self.client.get("/api/v1/auth/me?token=super_secret_token")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("strictly forbidden", resp.json()["detail"])


if __name__ == "__main__":
    unittest.main()

