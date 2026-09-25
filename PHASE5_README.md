# Phase 5: React Frontend

## What's implemented in this phase

**Project setup** — Vite + React 18, `react-router-dom` for routing. No UI component
library: per Section 1's choice, this uses hand-written, clean modern CSS
(`src/index.css`) rather than Material UI, to keep the bundle small and avoid a large
theming layer for what's fundamentally a handful of forms and buttons. (If you'd rather
have MUI, say so and I'll swap the components over — the structure underneath won't
change.)

**`utils/base64url.js`** — the unglamorous but critical piece every WebAuthn frontend
needs: converting between the Base64URL strings the backend's JSON uses and the raw
`ArrayBuffer`s `navigator.credentials.create()`/`.get()` require. I wrote this by hand
rather than relying on the newer `PublicKeyCredential.parseCreationOptionsFromJSON` /
`credential.toJSON()` browser built-ins (added around 2024) specifically for **Section 16
browser compatibility** — this approach works on every browser that has supported WebAuthn
at all since ~2019, not just the last couple of years' releases.

**`services/webauthnService.js`** — the actual ceremonies:
- `isWebAuthnSupported()` / `isPlatformAuthenticatorAvailable()` — feature detection for
  the Section 12 "browser doesn't support WebAuthn" message and for deciding when to hint
  at biometrics vs. a generic passkey prompt. Availability is only ever used for *messaging*
  — never to gate the button itself, since a laptop with no fingerprint reader (Section 16)
  should still work via PIN or a security key, and the app has no way to know in advance
  which the OS will offer.
- `registerPasskey(deviceName)` / `loginWithPasskey(email)` — fetch options from the
  backend, transform them into the shape `navigator.credentials` expects, invoke it (this
  is the exact moment Windows Hello / Touch ID / Face ID / Android biometrics / a YubiKey
  prompt appears — entirely outside the app's control or visibility), then serialize the
  signed result back to the JSON shape the backend's `RegistrationVerificationRequest` /
  `AuthenticationVerificationRequest` expect and POST it for verification.
- `mapCeremonyError` — translates the browser's `DOMException` types (user cancelled,
  already-registered authenticator, insecure context) into messages a person can act on.

**`hooks/useWebAuthn.js`** — thin React wrapper exposing `busy`/`error`/`supported` state
so components don't each reimplement loading/error handling.

**`hooks/useAuth.jsx`** — the only client-side "auth state" that exists: on mount, it asks
`GET /api/auth/me` whether the session cookie is still valid, and holds the resulting user
object in memory. There is deliberately no token stored anywhere in JS — the HttpOnly
cookie is the sole credential, consistent with the backend's `SessionService` design.

**Pages** (Sections 3/4/12/13):
- `pages/Login.jsx` — matches the mockup: a prominent usernameless "Sign in with Passkey"
  button up top, then email + "Continue", which reveals both an email-scoped passkey option
  and a password fallback.
- `pages/Register.jsx` — creates the account, then immediately prompts "Add a passkey"
  (skippable) — matching the exact UX flow described in Section 3.
- `pages/Dashboard.jsx` — minimal landing page after login.
- `pages/SecuritySettings.jsx` — can add a new passkey today (the backend already supports
  it); the full device list with rename/remove/last-used is explicitly called out as coming
  in **Phase 6**, since that needs new backend endpoints this phase didn't build yet.

**`ProtectedRoute`** — redirects to `/login` if `useAuth()` has no user once the initial
`/me` check resolves.

## Running it locally
```
cd frontend
npm install
npm run dev
```
Vite's dev server proxies `/api` to `http://localhost:8080` (see `vite.config.js`), and
`http://localhost:5173` counts as a WebAuthn "secure context" without needing a local TLS
certificate — more on this in Phase 9's local-dev instructions.

## What's next (Phase 6)
Backend: `GET /api/settings/credentials` (list), `PATCH .../{id}` (rename),
`DELETE .../{id}` (remove) — plus wiring `SecuritySettingsPage` up to actually render the
list from Section 15's mockup (Windows Laptop / MacBook / Android Phone, each with
last-used time and a Remove button).
