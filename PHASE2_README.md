# Phase 2: Spring Boot Backend + Database

## What's implemented in this phase

**Maven project** (`backend/pom.xml`)
Spring Boot 3.3.4 / Java 21, with: Web, Validation, Security, Data JPA, PostgreSQL driver,
Flyway, `webauthn4j-core` (WebAuthn ceremony verification), Bucket4j (rate limiting),
Lombok, and test dependencies (JUnit via spring-boot-starter-test, H2 for repository tests).

**Entities** (`entity/`)
- `User` — account row, including the opaque `webauthnUserHandle` kept separate from email
  (so no PII leaks into credential metadata that syncs across a user's devices).
- `WebAuthnCredential` — one row per registered passkey/security key, storing only the
  **public** key, credential ID, sign counter, AAGUID (authenticator model, not per-device ID),
  and a user-editable device label.
- `AuditLog` — append-only security event trail.

**Repositories** (`repository/`) — Spring Data JPA interfaces for all three entities, plus
lookups needed later (by email, by credential ID, by user handle).

**Database schema** (`db/migration/V1__init_schema.sql`, run automatically by Flyway on boot)
Four tables exactly as specified, plus a fifth (`webauthn_challenges`) that the spec's flows
require even though it wasn't explicitly listed in Section 7 — WebAuthn is fundamentally a
challenge-response protocol, so challenges need a durable, expiring, single-use store to
prevent replay attacks (this becomes important in Phase 3/4):

| Table | Purpose |
|---|---|
| `users` | accounts |
| `webauthn_credentials` | registered authenticators (public keys only) |
| `webauthn_challenges` | short-lived, single-use registration/login challenges |
| `sessions` | server-side session records, enabling central revocation |
| `audit_logs` | security event log |

Every column has an inline `COMMENT ON COLUMN` explaining its purpose — see the SQL file directly.

**Configuration** (`application.yml`)
- Postgres connection via env vars (`DATABASE_URL`, etc.)
- `ddl-auto: validate` — Hibernate never auto-generates schema; Flyway owns it, so what's in
  the DB always matches a reviewed migration file.
- WebAuthn RP ID/name/origin/challenge-TTL, all externalized (important: these differ between
  local dev and production — covered in Phase 9).
- A `prod` profile that forces `Secure` + `SameSite=Strict` cookies.

**Local Postgres** (`docker-compose.yml`) — one command (`docker compose up -d`) gets a
Postgres 16 instance with the right DB/user/password matching the defaults above.

## Note on session design
Rather than Spring Session's auto-managed tables, I implemented `sessions` as the custom
table you specified in Section 7, with session management handled explicitly in
`SessionService` (built in Phase 4) — this gives us direct control to store only a
SHA-256 hash of the session token (never the raw cookie value) and to support the
per-device "sign out this session" UI in `/settings/security`.

## What's next (Phase 3)
WebAuthn **registration**: `WebAuthnController`, `WebAuthnService`, the
`PublicKeyCredentialCreationOptions` generation, challenge persistence, and the
`/register/verify` endpoint that validates the attestation and stores the new credential.

## A note on verification
I can't run `mvn` in this environment (no access to Maven Central from this sandbox), so this
code hasn't been compiled here. I've been careful with imports and Spring Boot 3.3/Jakarta EE
conventions, but please run `mvn clean install` on your machine as the first step and report
back any compile errors — I'll fix them immediately.
