# Verification Notes

This documents exactly what was actually run and checked, so "should work" isn't a guess.

## Frontend: actually built and run, real bug found and fixed

```
cd frontend && npm install && npm run build
```

This genuinely ran. First attempt **failed** with:
```
Could not resolve "../hooks/useAuth.jsx" from "src/components/auth/ProtectedRoute.jsx"
```
`ProtectedRoute.jsx` lives two directories below `src/` (`src/components/auth/`), so it
needed `../../hooks/useAuth.jsx`, not `../hooks/useAuth.jsx`. Fixed, then verified:
- `npm run build` — succeeds, produces `dist/index.html` + hashed JS/CSS bundles
- `npm run lint` — zero errors (an `.eslintrc.cjs` was also missing and has been added)
- `npm run dev` — dev server actually starts and serves the app; confirmed with a real
  `curl` against `http://localhost:5173/` returning `200` and the expected HTML

## Backend: cannot be compiled in this environment — here's exactly why, and what was
## done instead

This sandbox's network is allow-listed to a fixed set of domains for security reasons, and
`repo.maven.apache.org` (Maven Central) isn't on it:
```
$ mvn compile
[FATAL] Non-resolvable parent POM for com.example:auth:0.1.0: ...
status: 403 Forbidden
```
That's not a project problem — it's this environment refusing the connection. **On your own
machine, with normal internet access, this will resolve dependencies and build normally.**

Since I couldn't get a real compiler signal, I did the next most rigorous thing available:
a systematic static cross-reference of the entire backend, checking things a compiler would
catch. Specifically, and automatically (not by eyeballing):
- Every `import com.example.auth.*` (33 of them) resolves to a file that actually exists
  at that path — **zero missing**.
- Every constructor that's manually instantiated with `new` (the three filter beans in
  `SecurityConfig`, plus `Argon2PasswordEncoder`) has its argument list checked against the
  real constructor signature — **all match**.
- Every hand-built DTO record (`RegistrationOptionsResponse`, `AuthenticationOptionsResponse`,
  `UserResponse`, `CredentialResponse`, `AppProperties`, `WebAuthnProperties`, etc.) had its
  declared field list compared against every `new X(...)` call site, field-by-field, in
  order — **all match**.
- Every custom repository method actually called from service/controller code (e.g.
  `countByUser`, `findByChallengeAndConsumedFalse`, `findAllByUserIdAndRevokedFalse`) is
  cross-checked against what's declared on that repository interface — **zero mismatches**.
- Every entity field accessed via a Lombok-generated getter/setter (`credential.getAaguid()`,
  `user.setLockedUntil()`, `session.setRevoked()`, etc.) is cross-checked against that
  entity's actual `@Getter`/`@Setter`-annotated fields — **zero mismatches**.
- Every `.java` file (main and test, 55 files total) has balanced braces — **zero unbalanced**.
- All five test classes' `new ServiceUnderTest(...)` calls match the real constructor
  signatures of the services they're testing — **all match**.

This catches the class of bug a compiler catches for *our own code* — wrong argument counts,
typos in method names, broken imports, mismatched field lists. It does **not** catch type
mismatches within an expression, or confirm the `webauthn4j` library's actual method
signatures match what's assumed (that's the one category of risk that's inherent to not
having the real dependency available, and it's flagged specifically — see
`PHASE4_README.md`'s `PersistedCredentialRecord` section and `PHASE7_README.md`'s Bucket4j
note, which remain the two places to check first if `mvn compile` on your machine finds
anything).

## What this means practically

Run `mvn clean install` as your very first step after downloading this project. If it
succeeds outright, you're in a fully verified state end-to-end (frontend confirmed built and
served here; backend now confirmed by a real compiler on your machine). If it doesn't, the
two README sections above tell you exactly where to look before you go hunting.
