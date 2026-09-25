# Passkey Authentication App

A browser-based authentication system: React + Spring Boot + PostgreSQL, with WebAuthn/
passkeys as the primary sign-in method and a password fallback.

**Before anything else, read `VERIFICATION.md`** — it documents exactly what was actually
built and run to confirm this works (the frontend was really built and served; the backend
was rigorously cross-checked but could not be compiled in the sandbox that generated it, for
a documented network reason) and exactly what to check first if `mvn compile` hits anything
on your machine.

## Structure
```
backend/     Spring Boot API (Java 21)
frontend/    React app (Vite) — the browser UI and the WebAuthn ceremony calls
e2e/         Playwright end-to-end tests using a CDP virtual authenticator
docker-compose.yml         Local dev: just Postgres
docker-compose.prod.yml    Full production stack: Postgres + backend + Nginx/frontend + certbot
```

---

## Run it: local development (three terminals)

**Terminal 1 — database**
```bash
docker compose up -d
```

**Terminal 2 — backend** (http://localhost:8080)
```bash
cd backend
cp .env.example .env
mvn clean install
mvn spring-boot:run
```

**Terminal 3 — frontend** (http://localhost:5173)
```bash
cd frontend
npm install
npm run dev
```

Then open **http://localhost:5173/register** — `http://localhost` is treated as a secure
context by every browser specifically so WebAuthn works here with no TLS certificate needed.

To stop: Ctrl-C in terminals 2 and 3, then `docker compose down` (add `-v` to also wipe the
database volume).

---

## Run it: everything in Docker (closer to production, still local)

```bash
cp .env.prod.example .env
# edit .env: for local testing, set DOMAIN_NAME=localhost — TLS/certbot steps below
# don't apply to a pure localhost run, so see "Production deployment" for the real domain case
docker compose -f docker-compose.prod.yml up -d --build postgres backend
```
The `frontend` service in that compose file expects TLS certs (production use — see below);
for an all-Docker *local* run, use the dev `docker-compose.yml` for Postgres and run the
backend/frontend containers individually, or just use the three-terminal flow above, which is
simpler for local iteration.

---

## Run it: production deployment (real domain, real HTTPS)

```bash
git clone <your-repo> && cd <your-repo>
cp .env.prod.example .env
# edit .env: DOMAIN_NAME (DNS A record must already point here), DATABASE_PASSWORD,
# SESSION_SECRET (generate with: openssl rand -base64 48), CERTBOT_EMAIL

docker compose -f docker-compose.prod.yml up -d --build postgres backend frontend

# One-time certificate issuance (only needed once — the certbot service then renews it):
docker compose -f docker-compose.prod.yml run --rm certbot \
  certonly --webroot -w /var/www/certbot \
  -d "$DOMAIN_NAME" --email "$CERTBOT_EMAIL" --agree-tos --no-eff-email

docker compose -f docker-compose.prod.yml restart frontend
docker compose -f docker-compose.prod.yml up -d certbot
```
Full details, including why `DOMAIN_NAME` has to be exact, are in `PHASE9_README.md`.

---

## Run the tests
```bash
cd backend && mvn test                 # unit + integration tests (H2, no Docker needed)

cd e2e && npm install && npx playwright install chromium && npm test
# ^ needs the backend AND frontend actually running (see local dev steps above)
```

---

## How this was built
Developed in nine phases, each with its own README documenting what was built, why, and —
where relevant — what to double check:

1. `PHASE2_README.md` — Spring Boot backend skeleton + database schema
2. `PHASE3_README.md` — WebAuthn registration
3. `PHASE4_README.md` — WebAuthn login (flags the one file most likely to need a
   version-specific tweak: `PersistedCredentialRecord.java`)
4. `PHASE5_README.md` — React frontend
5. `PHASE6_README.md` — Passkey/device management (documents a real lazy-loading bug that
   was found and fixed)
6. `PHASE7_README.md` — Security hardening (full table mapping every Section 10 requirement
   to where it's implemented)
7. `PHASE8_README.md` — Testing (full table mapping all 20 Section 19 scenarios to what
   actually covers each one)
8. `PHASE9_README.md` — Docker + deployment, browser compatibility, and an honest note on
   Account Recovery (Section 14), which fell outside the 9-phase plan and isn't built
9. `VERIFICATION.md` — what was actually run and checked after all nine phases, including a
   real bug this caught and fixed

# passkey-beckend
