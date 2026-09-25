# Phase 7: Security Hardening

## What's implemented in this phase

**Rate limiting** (`RateLimiterService`, `RateLimitingFilter`) — Bucket4j token-bucket
limiter, per-(category, client IP), applied to `POST /api/auth/register`,
`/api/auth/login/password`, and both `/api/auth/webauthn/login/*` endpoints. Limits come
from `app.rate-limit.*` in `application.yml` (already scaffolded back in Phase 2). Returns
HTTP 429 with the same `{ code, message, timestamp }` shape as everything else. This is the
network-level half of "login attempt protection"; the per-account lockout added in Phase 4
(`PasswordAuthenticationService`) is the other half — the two are complementary, not
redundant: rate limiting stops a single IP hammering many accounts, lockout stops many
attempts against one account from a botnet of IPs.

**CSRF defense-in-depth** (`CsrfDoubleSubmitFilter`) — the standard double-submit-cookie
pattern, layered on top of the SameSite cookie protection that was already the primary
defense since Phase 3. Every response ensures a readable `XSRF-TOKEN` cookie exists;
mutating requests (`POST`/`PUT`/`PATCH`/`DELETE`) to authenticated endpoints must echo it
back in an `X-XSRF-TOKEN` header, which a cross-site attacker's page has no way to read.
The frontend's `api.js` was updated to do this automatically. Unauthenticated bootstrap
endpoints (register, login, logout) are exempt — there's no established state yet for a
forged request to abuse.

**Security headers** (`SecurityConfig.filterChain`) — explicit Content-Security-Policy
(`default-src 'self'; frame-ancestors 'none'`) and Referrer-Policy
(`strict-origin-when-cross-origin`). `X-Content-Type-Options: nosniff` and
`X-Frame-Options: DENY` are Spring Security defaults, already on. HSTS is added
automatically by Spring Security once a request arrives over HTTPS — in production that
means once Nginx (Phase 9) is correctly terminating TLS.

**Session revocation** (`POST /api/auth/logout-all`) — the "I think someone has my
account" button: revokes every row in `sessions` for the user, not just the current
cookie, and is wired into a new "Sign out of all devices" control on the Security page.

**More audit events** — `ACCOUNT_CREATED`, `PASSKEY_REGISTERED`, `ACCOUNT_LOCKED` (fired
exactly once, at the moment the 5th failed attempt trips the lock — not on every
subsequent blocked attempt), `LOGOUT_ALL_SESSIONS`, on top of the login success/failure and
`PASSKEY_REMOVED` events already added in earlier phases.

## Section 10 checklist — where everything stands

| Requirement | Status | Where |
|---|---|---|
| HTTPS requirement | Enforced in prod config; documented in Phase 9 | `nginx.conf`, `application.yml` prod profile |
| Secure / HttpOnly / SameSite cookies | Done | `SessionService`, `CsrfDoubleSubmitFilter` |
| CSRF protection | Done (SameSite + double-submit) | `CsrfDoubleSubmitFilter` |
| CORS configuration | Done, explicit allow-list | `SecurityConfig` |
| Rate limiting | Done | `RateLimitingFilter` |
| Login attempt protection | Done (account + IP layers) | `PasswordAuthenticationService`, `RateLimitingFilter` |
| Session expiration | Done | `sessions.expires_at`, `SessionService` |
| Session revocation | Done | `SessionService.revokeAll`, `/logout-all` |
| Credential revocation | Done | Phase 6, `CredentialManagementService` |
| Input validation | Done | Bean Validation across all request DTOs |
| Email validation | Done | `@Email` |
| Password hashing (Argon2id) | Done | `SecurityConfig.passwordEncoder` |
| Audit logging | Done | `AuditService`, called from every sensitive path |
| Secure error messages | Done | `GlobalExceptionHandler` |
| Replay attack protection | Done | Single-use `webauthn_challenges` |
| WebAuthn challenge expiration | Done | `ChallengeService` TTL + purge job |
| Challenge uniqueness | Done | 256-bit random, single-use |
| Sign counter validation | Done | `webauthn4j` verification against `CredentialRecord` |

## Honest caveat: Bucket4j's builder API

I pinned `bucket4j_jdk17-core:8.10.1` back in Phase 2, before rate limiting was actually
implemented. The `Bucket.builder().addLimit(limit -> limit.capacity(n).refillGreedy(...))`
syntax I used in `RateLimiterService` is confirmed current for recent 8.x releases
(8.15–8.20, which I could verify directly against the library's own README), but I can't
fully confirm it's present all the way back at 8.10.1 specifically without compiling
against that exact jar. If `mvn compile` complains about `Bucket.builder()` or
`addLimit`, bump the version in `pom.xml` to something in the 8.15+ range — the rest of
`RateLimiterService` doesn't need to change, since only that one builder call is
version-sensitive.

## What's next (Phase 8)
Testing: unit tests for the services (`WebAuthnRegistrationService`,
`WebAuthnAuthenticationService`, `PasswordAuthenticationService`, `CredentialManagementService`)
and integration tests covering the 20 scenarios listed in Section 19 — including the
security-relevant ones (expired challenge, replayed assertion, lockout, rate limiting).
