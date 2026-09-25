# Phase 6: Passkey / Device Management

## What's implemented in this phase

**`GET /api/settings/credentials`** — lists the signed-in user's registered credentials,
backing the `/settings/security` page from Section 15.

**`PATCH /api/settings/credentials/{id}`** — renames a credential's `device_name`.

**`DELETE /api/settings/credentials/{id}`** — removes a credential, with one safety rule
from the Section 14 threat model: if the credential being removed is the user's *only*
sign-in method (no fallback password, and no other passkey), the request is rejected with
a clear `LAST_SIGN_IN_METHOD` error instead of silently locking the account. Every
lookup in `CredentialManagementService` also checks ownership and returns a plain 404 (not
403) for a credential that belongs to someone else, so this endpoint can't be used to probe
which credential IDs exist.

**Frontend**: `credentialService.js`, `CredentialRow.jsx` (inline rename, remove with a
confirm dialog, relative "last used" time, an icon distinguishing passkeys from security
keys), and `SecuritySettingsPage` now fully wired to the real list instead of the Phase 5
placeholder.

## A bug I caught and fixed while wiring this up

Building the credential list surfaced a real problem in `UserResponse`, which I'd written
back in Phase 3/4 to compute `passkeyCount` from `user.getCredentials().size()`. With
`spring.jpa.open-in-view: false` (set deliberately in Phase 2, which is the correct
production setting), that lazy `@OneToMany` collection is only safe to touch **inside** the
transaction that loaded the `User` — and every controller was building the response *after*
its service call's `@Transactional` method had already returned. This would have thrown
`LazyInitializationException` on `/api/auth/me`, `/register`, and both login endpoints the
first time a returning user (one with an already-persisted `credentials` collection) hit
them.

Fixed by:
- `UserResponse.from(user, passkeyCount)` now takes the count as a plain parameter instead
  of reaching into the lazy collection itself.
- `UserService.toUserResponse(user)` is the one place that count is computed — via
  `WebAuthnCredentialRepository.countByUser()`, a direct query, inside its own
  `@Transactional(readOnly = true)` method — and every controller now calls this instead of
  `UserResponse.from(user)` directly.

I'm flagging this explicitly rather than quietly patching it, because it's exactly the kind
of bug that only shows up once you have a *second* request touching an *already-persisted*
entity — it wouldn't have appeared in quick manual testing of just the registration flow,
which is why I want you to know it was there and how it's fixed now, not just that it's fixed.

## What's next (Phase 7)
Security hardening: Bucket4j-based IP rate limiting (login/register attempt protection
beyond the per-account lockout already in `PasswordAuthenticationService`), CSRF
defense-in-depth (double-submit cookie), stricter input validation, and a review pass
against the full Section 10 checklist.
