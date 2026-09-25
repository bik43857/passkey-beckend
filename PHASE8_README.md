# Phase 8: Testing

## Testing strategy — three layers, on purpose

WebAuthn's whole design point is that the browser/OS does the cryptographic and biometric
work, invisibly to the application. That's great for users and for security, but it means a
meaningful chunk of Section 19's scenarios are, by construction, **not unit-testable** — a
JVM test has no fingerprint reader and no Face ID sensor to call. So this phase uses three
layers, each covering what it's actually capable of covering:

1. **JUnit unit tests** (`backend/src/test/java/.../service/`) — pure business logic with
   Mockito-mocked repositories: challenge lifecycle, account lockout, credential ownership/
   last-sign-in-method rules, session expiry/revocation. Fast, no Spring context, no DB.
2. **Spring Boot integration tests** (`backend/src/test/java/.../controller/`) — real HTTP
   requests via MockMvc against a real (H2) database and the real filter chain (rate
   limiting, CSRF, session cookies all genuinely execute). WebAuthn ceremony *endpoints* are
   tested here too, but with `WebAuthnRegistrationService`/`WebAuthnAuthenticationService`
   mocked out — this verifies our own HTTP contract, auth guards, and error mapping without
   needing real cryptographic material.
3. **Playwright end-to-end tests** (`e2e/tests/passkey.spec.js`) — the only layer that
   exercises genuine WebAuthn cryptography, using Chrome DevTools Protocol's virtual
   authenticator (`WebAuthn.addVirtualAuthenticator`) so `navigator.credentials.create()`/
   `.get()` run for real, against the real frontend and real backend, with no human present.

## Running the tests

```
# Backend unit + integration tests
cd backend
mvn test

# End-to-end (needs the backend AND frontend actually running)
cd e2e
npm install
npx playwright install chromium
npm test
```

## Section 19 scenario-by-scenario mapping

| # | Scenario | Covered by |
|---|---|---|
| 1 | Register with password | `AuthFlowIntegrationTest` |
| 2 | Register passkey | `e2e/passkey.spec.js` (real ceremony); HTTP contract in `WebAuthnControllerTest` |
| 3 | Login with passkey | `e2e/passkey.spec.js` |
| 4 | Login using fingerprint | **Manual, real hardware** — see note below |
| 5 | Login using Windows Hello PIN | **Manual, real hardware** |
| 6 | Login using Windows Hello face | **Manual, real hardware** |
| 7 | Login using mobile passkey | **Manual, real hardware** |
| 8 | Login using security key | **Manual, real hardware** (or a `transport: 'usb'` virtual authenticator variant — see below) |
| 9 | Login from a new browser | Partially: `e2e` suite can detach/reattach a virtual authenticator; real cross-device passkey sync additionally needs a real Apple/Google account, which is **manual only** |
| 10 | Remove passkey | `CredentialManagementServiceTest`, `CredentialControllerIntegrationTest` |
| 11 | Add multiple passkeys | `CredentialControllerIntegrationTest` (list), `e2e` suite can be extended to add a second virtual authenticator |
| 12 | Expired WebAuthn challenge | `ChallengeServiceTest` (unit level, deterministic — doesn't need a real wall-clock wait) |
| 13 | Invalid WebAuthn response | `ChallengeServiceTest` (mismatched ceremony type), `WebAuthnControllerTest` (malformed JSON → 400) |
| 14 | Replay attack | `ChallengeServiceTest.consumingTheSameChallengeTwiceFailsTheSecondTime` |
| 15 | Session expiration | `SessionServiceTest.expiredSessionDoesNotResolveToAUser` |
| 16 | Logout | `AuthFlowIntegrationTest` |
| 17 | Password fallback | `AuthFlowIntegrationTest`, `PasswordAuthenticationServiceTest` |
| 18 | Unsupported browser | Frontend-only concern — `isWebAuthnSupported()` is plain feature detection with no server round-trip to test; verify manually by disabling `window.PublicKeyCredential` in devtools |
| 19 | No biometric hardware | `e2e/passkey.spec.js` (`hasUserVerification: false` virtual authenticator) covers the "device can't do it" case; the "PIN instead of biometric" case is covered implicitly — the app never distinguishes them, by design |
| 20 | Lost device | `AuthController.logoutAll` + `CredentialManagementService.remove` — the two together ARE the answer to "I lost my device": revoke every session, then remove that device's credential once you're back in from another one. Covered by `CredentialControllerIntegrationTest` and `CsrfIntegrationTest` (which exercises `/logout-all`) |

Plus tests beyond the original 20, covering things the rest of the build added along the
way: rate limiting (`RateLimitingIntegrationTest`), CSRF double-submit
(`CsrfIntegrationTest`), and account-enumeration resistance (identical error messages
regardless of which failure reason, in both `PasswordAuthenticationServiceTest` and
`AuthFlowIntegrationTest`).

## Why five scenarios are marked "manual, real hardware" and not faked

I could have mocked deeper — e.g., stub out the browser's `navigator.credentials` object in
a Playwright test and claim it exercises "Windows Hello face" — but that wouldn't actually
be testing anything Windows-Hello-specific, because **the app has no code path that knows
which biometric method was used**. That's not a gap in test coverage; it's WebAuthn working
exactly as designed (Phase 1's architecture explanation). Writing a test named
`testWindowsHelloFace` that's secretly identical to `testWindowsHelloFingerprint` would be
actively misleading about what's verified. The honest scope: automated tests prove the
*protocol and our server-side handling* are correct; a short manual checklist on real
devices before each release is what actually confirms the UX on each platform, and that
belongs in a release runbook, not a CI test file.

## What I did not add: a WebAuthnRegistrationServiceTest with real crypto

I considered hand-building a real WebAuthn test vector (an actual signed
`CollectedClientData`/`AuthenticatorData`/attestation, generated with a real key pair) to
unit-test `WebAuthnRegistrationService.verifyAndSave` without mocking `webauthn4j` at all.
I decided against it: doing that correctly requires either a second crypto library in the
test scope just to generate a valid signature, or pinning to one specific authenticator's
exact byte-for-byte output — and if I got any byte wrong, the test would fail for reasons
having nothing to do with your code. The Playwright/CDP virtual-authenticator approach gets
the same real-cryptography coverage with far less fragility, which is why the e2e layer
exists at all rather than stopping at mocked unit tests.

## What's next (Phase 9)
Docker Compose for the full stack, Nginx reverse proxy configuration, and production
deployment instructions (Section 18) — plus finishing the local-dev setup instructions
(Section 17) that tie Phases 1–8 together into something you can actually run end to end.
