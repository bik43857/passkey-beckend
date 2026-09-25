# Phase 4: WebAuthn Login

## What's implemented in this phase

**`POST /api/auth/webauthn/login/options`** (`WebAuthnAuthenticationService.generateOptions`)
- Builds `PublicKeyCredentialRequestOptions` JSON for `navigator.credentials.get()`.
- **Email-first flow** (Section 4): if an email is supplied and matches an account,
  `allowCredentials` is narrowed to that user's registered authenticators.
- **Usernameless flow** (Section 13): if no email is supplied (or it doesn't match any
  account — deliberately indistinguishable, to prevent email enumeration through this
  endpoint), `allowCredentials` is empty and the browser instead surfaces every
  discoverable passkey it has for this site. We don't know *which* user is logging in
  until `verify` tells us, from the credential ID the browser picked.
- Issues a single-use challenge exactly as in registration; for the usernameless case the
  challenge is stored with a null `user_id`.

**`POST /api/auth/webauthn/login/verify`** (`WebAuthnAuthenticationService.verifyAndLogin`)
- Parses the assertion, looks up the credential purely by `credential_id` (this is how we
  identify the user in the usernameless flow), and confirms it belongs to whichever user
  the challenge was bound to (skipped for the usernameless case, where any discoverable
  credential is acceptable by design).
- Verifies the signature against the **stored public key** and checks the sign counter
  moved forward, via `webAuthnManager.verify(...)` — this is the "sign counter validation"
  / clone-detection requirement from Section 10, enforced by the library itself using the
  `CredentialRecord` we reconstruct (see below).
- On success: updates `sign_count` and `last_used_at` on the credential, opens a session
  (same `SessionService` as password login), and writes an `AuditLog` row.

**`POST /api/auth/login/password`** (`PasswordAuthenticationService`) — the fallback flow
(Section 4/G), with account-level lockout: 5 failed attempts locks the account for 15
minutes (`User.status = LOCKED`, `lockedUntil`). Every outcome — unknown email, no
password set on the account, wrong password — returns the identical generic
"Invalid email or password" error, so this endpoint can't be used to enumerate accounts.

**`POST /api/auth/logout`** — clears the session cookie.

## The one file that needs your attention: `PersistedCredentialRecord`

This is genuinely the highest-risk file in the project, and I want to be direct about why.

To verify a login assertion, `webauthn4j` needs a `CredentialRecord` — normally you get one
"for free" right after registration, built directly from the raw `AttestationObject` the
browser sent (that's what the library's own quick-start example does). We don't keep that
raw object around; per your Section 7 schema, we store the **extracted** fields (public key,
credential ID, sign count, AAGUID) as clean columns instead of one opaque blob — which is
the right call for a real schema, but means at login time we have to *reconstruct* an
equivalent `CredentialRecord` from those columns rather than just deserializing one.

`PersistedCredentialRecord.from(...)` does that reconstruction. I'm confident about the data
being fed in (it's exactly what we stored). I'm less certain about three specific API
surface details, because `CredentialRecordImpl`'s exact constructor overloads and a couple of
enum factory methods have shifted slightly across `webauthn4j` 0.2x releases and I can't
compile against the real jar in this sandbox:

1. The `CredentialRecordImpl` constructor arg order/count (attestedCredentialData,
   attestationStatement, counter, uvInitialized, backupEligible, backupState, transports,
   clientExtensions, authenticatorExtensions) — if your resolved version's constructor
   differs, your IDE's autocomplete on `new CredentialRecordImpl(` will show you the real
   parameter list immediately.
2. `AuthenticatorTransport.create(String)` — the static factory that turns `"internal"` /
   `"usb"` etc. back into the enum-like value.
3. `new AAGUID(String)` / `AAGUID.ZERO` — reconstructing the authenticator model identifier
   from the string we stored.

None of these affect the actual cryptographic verification — that's entirely inside
`webAuthnManager.verify(...)`, which is the well-documented, stable part of the library.
Worst case here is a compile error in one file with a very localized, mechanical fix. Please
run `mvn compile`, and if this file is the one that breaks, paste me the error — I'll fix it
immediately using your project's actual resolved API.

## What's next (Phase 5)
The React frontend: Vite project setup, the WebAuthn browser API wrapper
(`useWebAuthn` hook — `navigator.credentials.create`/`.get()`, `toJSON()`/
`parseCreationOptionsFromJSON`), Login/Register pages, and the API client.
