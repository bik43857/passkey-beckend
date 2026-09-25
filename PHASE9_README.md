# Phase 9: Docker + Deployment

## Section 17: Local development setup

Three things run side by side; none of them need HTTPS locally, because `http://localhost`
is treated as a secure context by every browser specifically so WebAuthn development
doesn't require a local TLS certificate (Phase 5's `vite.config.js` comment covers this).

**1. Database**
```
docker compose up -d          # starts just Postgres, from the repo-root docker-compose.yml
```

**2. Backend**
```
cd backend
cp .env.example .env          # defaults already match the docker-compose Postgres
mvn clean install
mvn spring-boot:run
```
Runs on `http://localhost:8080`. `WEBAUTHN_RP_ID=localhost` and
`WEBAUTHN_ORIGIN=http://localhost:5173` in `.env.example` are already correct for this setup
— see Phase 3's README for why the RP ID/origin have to match exactly.

**3. Frontend**
```
cd frontend
npm install
npm run dev
```
Runs on `http://localhost:5173`, proxying `/api` to `:8080` (Vite config, Phase 5).

Open `http://localhost:5173/register` and you should be able to create an account and
register a passkey using your OS's platform authenticator (Windows Hello / Touch ID) or a
plugged-in security key.

## Section 18: Production deployment

**Architecture** (matches the diagram in the original spec exactly):
```
Browser → HTTPS → Nginx (frontend/nginx.conf) → React static files
                              ↓ /api
                          Spring Boot (backend) → PostgreSQL
```
Nginx and the backend share one Docker network; only Nginx's ports 80/443 are published to
the host. The backend is never directly reachable from outside.

**One-time setup, on the server:**
```
git clone <your repo> && cd <your repo>
cp .env.prod.example .env
# edit .env: set DOMAIN_NAME to your real domain (DNS A record must already
# point at this server), a strong DATABASE_PASSWORD, and SESSION_SECRET
# (openssl rand -base64 48)

# Bring up everything EXCEPT certbot's cert request first — Nginx needs to be
# serving the ACME http-01 challenge path before certbot can issue anything.
docker compose -f docker-compose.prod.yml up -d --build postgres backend frontend

# One-time certificate issuance (the recurring `certbot` service in the
# compose file only RENEWS an existing cert — it doesn't request the first one):
docker compose -f docker-compose.prod.yml run --rm certbot \
  certonly --webroot -w /var/www/certbot \
  -d "$DOMAIN_NAME" --email "$CERTBOT_EMAIL" --agree-tos --no-eff-email

# Nginx needs to pick up the now-existing certificate:
docker compose -f docker-compose.prod.yml restart frontend

# Start the renewal loop:
docker compose -f docker-compose.prod.yml up -d certbot
```

**Configuration that MUST be correct for WebAuthn to work at all in production:**
- `WEBAUTHN_RP_ID` = your bare domain (`auth.example.com`, no scheme) — see Phase 3's
  README on why this is checked byte-for-byte against what the browser reports.
- `WEBAUTHN_ORIGIN` = the full HTTPS origin (`https://auth.example.com`) — same-origin
  matching is enforced by `webauthn4j` on every ceremony.
- `SESSION_COOKIE_SECURE=true` and the `prod` Spring profile (both set automatically by
  `docker-compose.prod.yml`) — a `Secure` cookie is simply dropped by the browser over
  plain HTTP, so this has to be right before you can even log in.

**Redeploying after a code change:**
```
docker compose -f docker-compose.prod.yml up -d --build backend frontend
```
Postgres data persists in the `auth_pg_data` named volume across this — Flyway
(Phase 2) runs any new migrations automatically against the existing database on backend
startup.

## Section 16: Browser compatibility

| Browser | Windows | macOS | Linux | Android | iOS |
|---|---|---|---|---|---|
| Chrome | ✅ Windows Hello | ✅ Touch ID | ✅ security keys only (no platform authenticator) | ✅ fingerprint/face | N/A (iOS Chrome uses WebKit) |
| Edge | ✅ Windows Hello | — | — | — | — |
| Firefox | ✅ Windows Hello | ✅ Touch ID | ✅ security keys only | ✅ | ✅ (WebKit-based on iOS) |
| Safari | — | ✅ Touch ID | — | — | ✅ Face ID / Touch ID |

All current (last ~3 years) versions of every browser above implement WebAuthn Level 2 at
minimum, including discoverable credentials (needed for Section 13's usernameless flow).
Linux desktop generally has no OS-integrated platform authenticator, so users there rely on
a security key or the password fallback — the frontend's `isPlatformAuthenticatorAvailable()`
check (Phase 5) correctly reports `false` there and the UI degrades to a generic "Sign in
with Passkey" prompt rather than promising a fingerprint/face experience it can't deliver.

**When biometric hardware is unavailable** (Section 16's specific requirement): the app
never assumes it exists. `navigator.credentials.create()`/`.get()` are called identically
regardless of platform-authenticator availability; if the OS has no biometric sensor
enrolled, it falls back to its own PIN/password prompt (Windows Hello PIN, a macOS login
password, etc.) — entirely outside the app's code, exactly as designed. The password
fallback (Section 4/G) remains available at every step for users on browsers or devices
with no WebAuthn support at all.

---

## Project status after Phases 1–9

Everything in the original Phase 1–9 plan is built: architecture, database, backend
(registration + login + device management + hardening), frontend, tests, and deployment.

**One thing from the original spec that fell outside the 9-phase plan and is genuinely not
built yet: Section 14, Account Recovery** (recovery codes / recovery email / admin-assisted
recovery). Right now, an account with only a passkey and no fallback password, whose only
device is lost, has no recovery path — `CredentialManagementService` prevents removing a
last credential, but nothing yet helps a user who's already *locked out* get back in. This
wasn't an oversight I'm discovering now — it just isn't one of the nine phases you laid out
— but I want to flag it explicitly rather than let "all 9 phases done" imply full spec
coverage. Happy to build it as a Phase 10 if you'd like: the natural design is one-time
recovery codes (like GitHub/Google's), generated and shown once at passkey registration
time, hashed at rest exactly like the password.
