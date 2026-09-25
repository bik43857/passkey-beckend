# Phase 3: WebAuthn Registration

## What's implemented in this phase

**Session infrastructure** (pulled forward from Phase 4, since registering a passkey
requires an authenticated user):
- `entity/Session.java` + `SessionRepository` — matches the `sessions` table from Phase 2.
- `SessionService` — issues an HttpOnly/SameSite/(Secure in prod) cookie holding a random
  opaque token; the DB stores only a SHA-256 hash of that token, never the raw value. See
  the class-level Javadoc for why cookies were chosen over a JWT in localStorage.
- `SessionAuthenticationFilter` + `CurrentUserProvider` — resolve the cookie into a `User`
  and expose it to controllers via Spring Security's `Authentication`.
- `SecurityConfig` — stateless filter chain (we manage sessions ourselves, so Spring
  Security's own `HttpSession` is disabled), CORS locked to an explicit origin allow-list
  (required since we send credentials/cookies — `*` is not permitted with credentials), and
  an Argon2id `PasswordEncoder` bean (OWASP-recommended parameters).

**Account creation**
- `POST /api/auth/register` (`AuthController`) — creates the `User` row (email uniqueness
  checked, but the conflict error message is deliberately generic to avoid account
  enumeration), hashes the optional fallback password with Argon2id, generates the opaque
  `webauthn_user_handle`, and immediately opens a session — matching the UX flow in your
  spec where "Register Passkey" appears right after account creation with no separate
  login step.

**WebAuthn registration ceremony** (`WebAuthnRegistrationService`, `WebAuthnController`)
- `POST /api/auth/webauthn/register/options` — generates `PublicKeyCredentialCreationOptions`
  as hand-built JSON matching the W3C wire format (I deliberately don't serialize
  webauthn4j's internal options class directly — there's no single standard byte-array
  encoding for it, so a hand-written DTO keeps the contract explicit). Issues and persists
  a single-use challenge (`ChallengeService`), and excludes the user's already-registered
  credentials so the same authenticator can't register twice.
- `POST /api/auth/webauthn/register/verify` — takes the raw JSON from the browser's
  `publicKeyCredential.toJSON()`, verifies it with `webauthn4j` (`WebAuthnManager.verify`),
  confirms the challenge was one we issued *for this user* and hasn't been used before, then
  extracts and stores only the **public** key (COSE-encoded, CBOR-serialized), credential ID,
  sign counter, AAGUID, and transport hints.

**Challenge lifecycle** (`ChallengeService`) — issues 256-bit random challenges with a
configurable TTL, consumes them exactly once (the core of WebAuthn's replay protection),
and a `@Scheduled` job purges expired rows every 5 minutes.

**Error handling** (`GlobalExceptionHandler`) — WebAuthn verification failures return a
generic 401 without revealing *which* check failed (challenge vs. signature vs. origin),
per the Section 10 "secure error messages" requirement; full detail goes to the server log
only.

## Honest caveats on the webauthn4j integration

I don't have Maven Central access in this sandbox, so none of this has compiled. I
researched the webauthn4j API carefully (its docs, GitHub source, and version history) to
get method/package names right for `webauthn4j-core:0.28.6.RELEASE`, but three specific
spots are the most likely to need a small fix once you build it — please check these first
if `mvn compile` complains:

1. **`AuthenticatorData.isFlagBE()` / `isFlagBS()`** (backup-eligible / backup-state flags,
   in `WebAuthnRegistrationService`) — these accessor names have shifted across 0.2x
   releases as passkey support matured. I wrapped both calls in a `safeFlag()` helper that
   falls back to `false` rather than crashing, so worst case these two cosmetic fields are
   just wrong, not a build break — but check your version's `AuthenticatorData` javadoc for
   the current method names.
2. **`new DefaultChallenge(String)`** — I'm assuming this constructor takes a Base64URL
   string directly. If your pinned version only exposes a `byte[]` constructor, decode with
   `Base64UrlUtil.decode(challengeValue)` first.
3. **`AuthenticatorTransport.getValue()`** — used to build the CSV stored in
   `webauthn_credentials.transports`. If this doesn't compile, it's almost certainly
   `.name()` or `.getTransport()` instead — a one-line fix.

None of these affect the actual cryptographic verification logic (`webAuthnManager.verify(...)`),
which follows the library's documented quick-start pattern exactly.

## What's next (Phase 4)
WebAuthn **login**: `/login/options` (with both email-based and usernameless/discoverable
flows per Section 13), `/login/verify` (signature verification against the stored public
key + sign-counter replay check), and wiring successful verification into
`SessionService.createSession`. Also: the password-fallback login endpoint.
