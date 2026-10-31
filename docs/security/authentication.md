# SnareSight: Authentication Architecture & Password Hardening

**Phase:** 7 — Security Hardening and Defensive Response  
**Task:** P31 / 40  
**Status:** `COMPLETED AND VERIFIED`

---

## 1. Password Storage Standards

SnareSight strictly enforces modern salted password hashing:
- **Algorithm**: `bcrypt` (Blowfish-based cipher).
- **Work Factor**: `12` rounds (`gensalt(rounds=12)`), providing high resilience against GPU-accelerated dictionary attacks.
- **Salting Invariant**: Every password receives a cryptographically unique 128-bit random salt, ensuring identical plaintext passwords generate completely distinct hashes.
- **Zero Plaintext Rule**: Plaintext passwords are never stored in the database, never included in logs, and never returned in API responses.

---

## 2. Token Lifecycle & Session Management

Authentication is managed via signed JSON Web Tokens (JWT):
- **Signature Algorithm**: `HS256` signed with backend `JWT_SECRET_KEY`.
- **Claims**:
  - `sub`: Username.
  - `user_id`: UUID of user account.
  - `role`: System role (`ADMIN`, `ANALYST`, or `VIEWER`).
  - `jti`: Cryptographically unique UUID identifier for the individual session token.
  - `iat`: Issue timestamp.
  - `exp`: Expiration timestamp (default 60 minutes).
- **Transport Channels**:
  - `Authorization: Bearer <token>` HTTP header.
  - `snaresight_session` HttpOnly, SameSite=Lax cookie.
- **Logout Invalidation**:
  - Upon calling `POST /api/v1/auth/logout`, the token's `jti` is inserted into `revoked_tokens` table.
  - Subsequent requests presenting the revoked `jti` are rejected with `HTTP 401 Unauthorized`.

---

## 3. Anti-Enumeration & Rate Limiting

- **Generic Error Responses**: Failed authentication requests return an identical generic error message: `{"detail": "Invalid username or password"}` whether the username is invalid or the password is incorrect, completely preventing user enumeration.
- **Rate Limiting**: The sliding-window rate limiter limits consecutive failed login attempts to **5 attempts per 15 minutes** per IP/username pair. Excess attempts trigger `HTTP 429 Too Many Requests`.

