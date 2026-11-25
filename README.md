# authapp: Next.js + FastAPI + Redis authentication demo

A small but complete auth app: e-mail/password registration and login, Google and GitHub sign-in, a public guest dashboard, a signed-in dashboard, and server-enforced roles. Sessions use a short-lived access token plus a rotating refresh token with reuse detection, kept in Redis, and the frontend refreshes transparently through Axios interceptors. It is written to be compared and criticised, not to be trusted blindly: it has **not been audited** and is not guaranteed secure.

Built and tested on 25 November 2026.

## Stack and pinned versions

Versions are the latest stable releases on npm and PyPI on the build date, pinned exactly.

| Part | Versions |
|---|---|
| Frontend | next 16.4.6, react / react-dom 19.3.1, axios 1.21.1, typescript 5.9.3 |
| Backend | fastapi 0.165.0, sqlalchemy 2.1.9, alembic 1.20.1, pydantic 2.14.4, pyjwt 2.15.1, argon2-cffi 25.1.0, httpx 0.28.1, redis 8.2.0 |
| Stores | SQLite by default (any SQLAlchemy URL, e.g. Postgres), Redis 7+ |

TypeScript is pinned to 5.9.3 rather than 7.x (the new native compiler), to stay on the version Next.js 16 is built and tested against.

## Layout

```
backend/
  app/config.py             all settings, with production guards
  app/models.py             users, oauth_accounts
  app/permissions.py        role -> permissions
  app/deps.py               current_principal, require_permission(...)
  app/security/tokens.py    access JWT + refresh rotation (Lua script, Redis)
  app/security/csrf.py      Origin check + double-submit token
  app/security/cookies.py   cookie names/flags in one place
  app/security/ratelimit.py Redis fixed-window limiter
  app/security/redirects.py safe_next() against open redirects
  app/security/headers.py   API security headers
  app/oauth/state.py        OAuth transaction store, PKCE
  app/oauth/providers.py    Google (OIDC) and GitHub
  app/services.py           account-linking policy
  app/routers/              auth, oauth, dashboard
  app/cli.py                set-role / disable (revokes sessions)
  migrations/               Alembic, revision 0001_initial
  tests/                    pytest suite
frontend/
  lib/api.ts                Axios instance + interceptors (CSRF, refresh, replay)
  proxy.ts                  per-request nonce CSP (Next 16 "proxy", formerly middleware)
  next.config.ts            /api/* rewrite to FastAPI, static security headers
  app/                      /, /login, /register, /guest, /dashboard
```

## Setup

1. Start Redis: `docker compose up -d redis` (or a local `redis-server`).
2. Backend:
   ```
   cd backend
   python3 -m venv .venv && . .venv/bin/activate
   pip install -r requirements-dev.txt
   cp .env.example .env        # then set JWT_SECRET and the OAuth values
   alembic upgrade head
   uvicorn app.main:app_factory --factory --port 8000
   ```
3. Frontend:
   ```
   cd frontend
   npm ci            # or npm install
   cp .env.example .env.local
   npm run dev       # or: npm run build && npm start
   ```
4. Open http://localhost:3000. Only port 3000 is used by the browser; Next.js proxies `/api/*` to FastAPI.
5. Make yourself admin after registering: `python -m app.cli set-role you@example.com admin`.

Tests: `cd backend && pytest`. To also run every Redis-touching test against a real server: `TEST_REDIS_URL=redis://localhost:6379/15 pytest` (that database is flushed).

## OAuth client configuration you need to supply

**Google** (Google Cloud console, APIs and Services, Credentials, OAuth client ID, type "Web application"):
- Authorized redirect URI: `http://localhost:3000/api/auth/oauth/google/callback` (in production, your HTTPS origin with the same path).
- Scopes used: `openid email profile`. The OAuth consent screen must be configured; in "Testing" mode add your account as a test user.
- Put the values in `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`.

**GitHub** (Settings, Developer settings, OAuth Apps, New OAuth App):
- Homepage URL: `http://localhost:3000`.
- Authorization callback URL: `http://localhost:3000/api/auth/oauth/github/callback`.
- Scopes requested: `read:user user:email`. Put the values in `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`.

Without these, the provider buttons return 503 `provider_not_configured`; everything else works.

## How the flows work

### Tokens and Redis

- **Access token**: HS256 JWT, 10 minutes, in the HttpOnly cookie `__Host-access` (Path=/, SameSite=Strict, Secure). Claims: `iss, aud, sub, sid, typ=access, jti, iat, nbf, exp`. No role inside: roles and the active flag are read from the database on each request, so demotions and bans apply at once.
- **Refresh token**: opaque, `<family id>.<256-bit random>`, in `__Secure-refresh` with **Path=/api/auth**, so it is never sent to data endpoints. Only its SHA-256 is stored.
- **Family** = one login on one device. Redis keys:
  - `auth:fam:{fid}` hash: user, current token hash, absolute expiry. TTL = absolute session lifetime (30 days).
  - `auth:rt:{fid}:<hash>` hash: `active` or `rotated` (+ successor, time). TTL = idle timeout (14 days).
  - `auth:user:<uid>:fams` set, for "sign out everywhere".
  - `auth:oauth:<sha256(state)>` OAuth transactions, 10 minute TTL, read once with GETDEL.
  - `auth:rl:...` rate-limit counters.
- Every access-token check also confirms that `auth:fam:{sid}` still exists. That one Redis read per request makes logout, logout-everywhere, reuse detection and admin disable take effect immediately instead of after up to 10 minutes.

### Refresh rotation, reuse detection, concurrency

`POST /api/auth/refresh` runs one Lua script, so Redis executes it atomically:

1. Token is the family's current one and `active`: mark it `rotated` (pointing at its successor), store the new one, return a new access token and a new refresh cookie.
2. Token was rotated **less than 10 seconds ago** and its successor is still current: this is a parallel request that lost the race. Return a new access token only and **no** new refresh cookie (the browser already has the winner's cookie). The family stays alive.
3. Anything else with a known family (an older token, or a rotated one outside the window): treat as theft, **delete the family**. Attacker and victim are both signed out on that device, and their access tokens die too.
4. Past the absolute lifetime: `session_expired`.

The frontend avoids most races before they reach the server:
- **Single flight in a tab**: every request that gets 401 at the same time awaits the same refresh promise, then replays once (`_retried` stops loops). The dashboard fires `/me` and `/dashboard` in parallel on purpose, and has a "Fire 5 parallel requests" button to try it.
- **Across tabs**: `navigator.locks.request("auth-refresh")` serialises refreshes. A tab that gets the lock after another tab already refreshed (timestamp in localStorage newer than its failed request) just replays, because cookies are shared.
- **Logout broadcast**: a BroadcastChannel tells other tabs to go to the login page.
- The request interceptor attaches `X-CSRF-Token` to POST/PUT/PATCH/DELETE. A 403 `csrf_failed` (token rotated by a login in another tab) fetches a fresh token and retries once.
- Login, register, refresh and logout 401s never trigger a refresh.

The grace window follows the reasoning in RFC 9700 (OAuth 2.0 Security Best Current Practice) on refresh-token rotation: reuse of a rotated token means it leaked, so the whole family is revoked. Ten seconds is a trade-off, explained under Limits.

### Password login and registration

- Argon2id (argon2-cffi defaults) with transparent rehash when the parameters change.
- 12 to 128 character passwords. Display names are NFKC-normalised with control characters rejected. E-mails are validated and lower-cased.
- Request models use `extra="forbid"`, so `{"role": "admin"}` in a sign-up is a 422, not a privilege escalation.
- Unknown e-mail and wrong password give the same 401 `invalid_credentials`, and an unknown e-mail still runs one Argon2 verification so the timing is similar.
- FastAPI's default 422 echoes the submitted input (the password included). A custom handler returns only field and message.

### Google and GitHub

- Start (`GET /api/auth/oauth/{provider}/start?next=/path`): random `state`, PKCE verifier (S256), OIDC `nonce`, and a binding secret. Everything is stored server-side under `sha256(state)`; the browser gets the binding secret as `__Host-oauth_bind` (HttpOnly, SameSite=Lax so it survives the provider's redirect back).
- Callback: state consumed once (GETDEL), binding cookie must match (stops login CSRF, where an attacker makes a victim finish the attacker's login), provider must match, RFC 9207 `iss` checked if present, then the code is exchanged together with the PKCE verifier. Redirect URIs are built from `PUBLIC_ORIGIN`, never from the Host header.
- **Google**: the ID token is verified locally: RS256 only (no HS256 key confusion, no `alg=none`), key from Google's JWKS by `kid`, `iss` in Google's two issuer forms, `aud` = our client id, `azp` if present, `exp`/`iat` with 30 s leeway, and the `nonce`. Account key = `sub`.
- **GitHub** is OAuth, not OIDC, so there is no ID token. The identity is the numeric `id` from `GET /user`, called with the token we just got from GitHub's token endpoint. The e-mail is the one GitHub marks both `primary` and `verified` in `/user/emails`. The `login` (renamable, reusable) is never the key. GitHub's quirk of returning HTTP 200 with `{"error": ...}` is handled. GitHub added PKCE support for OAuth apps in 2025, so it is sent there too.
- Error codes in the redirect to `/login?error=` come from a fixed list, and the page maps them to fixed messages. Nothing from the provider is reflected.

### Account linking policy

1. Known `(provider, subject)`: sign in as that user.
2. Signed in and started via `POST /api/auth/oauth/{provider}/link` (authenticated and CSRF-checked): attach the identity to the current user.
3. Otherwise create a new user, but only with a provider-verified e-mail that no existing account uses.

There is **no automatic linking by e-mail**. Password sign-ups are unverified (there is no mail flow), so auto-linking would let someone register a victim's address first and then share the victim's account when they later use Google (pre-account-takeover). Instead the user sees: "An account with this e-mail already exists. Sign in with your password, then link the provider."

### Roles and permissions

`user`: `dashboard:read, profile:read`. `admin`: also `reports:read, users:read`. Each endpoint declares `Depends(require_permission("..."))`; unknown roles get nothing. The frontend hides the admin panel for UX only. Roles change only through `app/cli.py` (or the database), never through the API.

### CSRF, cookies, headers, redirects, rate limits

- **CSRF**: every POST needs an `Origin` (or `Referer`) exactly equal to `PUBLIC_ORIGIN` **and** an `X-CSRF-Token` header equal to the `__Host-csrf` cookie. JavaScript reads the token from `GET /api/auth/csrf` (same origin only: no CORS is configured). The token rotates on every login. SameSite=Strict is a third layer.
- **Session fixation**: every login creates a new family and a new CSRF token, and revokes whatever session the browser presented. Nothing the client sends is ever adopted as a session.
- **Cookies**: HttpOnly, Secure, SameSite, `__Host-`/`__Secure-` prefixes (so a subdomain cannot plant them), refresh path-scoped.
- **Headers**: the API sends `default-src 'none'` CSP, nosniff, DENY framing, `no-referrer` (keeps `code`/`state` out of Referer), `no-store`, HSTS in production. Next.js pages get a per-request **nonce CSP** with `strict-dynamic` via `proxy.ts`, as in the Next.js 16 CSP guide, plus nosniff, DENY framing, COOP and Permissions-Policy.
- **Open redirects**: `next` must be a same-site path. `//evil`, `/\evil`, schemes, control characters and over-long values fall back to `/dashboard`. Same rule on both ends.
- **Rate limits** (Redis, shared by all workers): login 30/min per IP and 10 per 15 min per e-mail, register 10/hour per IP, refresh 120/min per IP, OAuth start 30/min per IP. `X-Forwarded-For` is ignored unless `TRUST_FORWARDED_FOR=true`, and then only its right-most hop is used.

## Threat model (short)

| Threat | Mitigation here |
|---|---|
| XSS stealing tokens | Tokens are HttpOnly, never in JS or localStorage; nonce CSP; React escapes output |
| Stolen refresh token replayed | Rotation + reuse detection revokes the family; idle and absolute expiry |
| Stolen access token | 10 min lifetime; dies on logout/reuse/disable (family check) |
| CSRF / login CSRF | Origin check + double-submit token + SameSite=Strict; OAuth state bound to the browser |
| Session fixation | New family and CSRF token on every login |
| OAuth code interception / injection | PKCE S256, single-use state, binding cookie, exact redirect URIs |
| ID token forgery / replay / mix-up | Signature, iss, aud, azp, exp, nonce; per-provider callbacks; RFC 9207 iss |
| Pre-account-takeover via linking | No auto-link by e-mail; explicit, authenticated, CSRF-checked linking |
| Privilege escalation | extra="forbid"; roles from DB per request; permission per endpoint |
| Credential stuffing / brute force | Argon2id, per-IP and per-account limits, generic errors |
| Open redirect / header injection | safe_next on server and client |
| Redis dump | Only hashes of refresh tokens and OAuth state are stored |

## Limits and known gaps

- **Not audited.** Treat it as a study implementation.
- **XSS still wins while the page is open**: injected script cannot read the tokens, but it can make authenticated requests from the victim's browser. CSP lowers the odds; it does not remove them.
- **Grace window**: someone holding a token stolen *within 10 seconds* of its rotation gets one access token without triggering revocation. They cannot get a new refresh token that way. Set `REFRESH_REUSE_GRACE_S=0` to turn this off and accept occasional false logouts.
- **A lost refresh response** (network drop just after rotation) leaves the browser with the old token; after 10 s its next refresh counts as reuse and signs that device out. Safe, slightly annoying.
- **Registration reveals that an e-mail is taken** (409). Hiding that needs e-mail verification, which is out of scope, as are password reset, MFA, unlinking providers and an account-settings page.
- **Rate limiting** is a fixed window per IP or e-mail. It slows attackers; it does not stop distributed attacks. The per-e-mail limit can be used to lock a known user out for 15 minutes.
- **HS256** means the API that verifies access tokens can also mint them. Fine for one service; use EdDSA/RS256 with key rotation (`kid`) if other services must verify.
- **Redis is a security dependency**: if it is down, nobody can authenticate (fail closed). In production it needs auth/ACLs, TLS, persistence (AOF), and no public exposure.
- Google's JWKS is cached for an hour by PyJWKClient; a key-rotation fetch failure fails the login (closed).
- The Next.js dev server needs `'unsafe-eval'` in the CSP; it is only added when `NODE_ENV=development`.

## What was tested (25 November 2026)

- **Backend pytest: 85 test cases.** 68 use Redis and run twice, once against fakeredis (real Lua through lupa) and once against a real redis-server 8.0.5, so **153 runs, all passing**. Without `TEST_REDIS_URL`: 85 passed, 68 skipped.
- Covered: registration/login normal and failing cases, cookie flags, normalisation, mass assignment, no password echo, Argon2 and rehash, CSRF (missing, wrong, foreign/look-alike/missing Origin, rotation), rate limits (and spoofed X-Forwarded-For), security headers, refresh rotation, reuse outside grace revoking the family, grace path, grace limited to the immediate predecessor, **20 threads refreshing the same token at once (exactly 1 rotation, 19 grace)**, access expiry then refresh, idle and absolute lifetimes, refresh cookie path scoping, forged access tokens (bad signature, alg=none, wrong key, aud, typ, sub/sid mismatch), malformed refresh tokens, logout, logout-everywhere, session fixation, no plaintext tokens in Redis, role changes taking effect immediately, admin endpoints, Google (PKCE verifier matches challenge, wrong aud/iss/azp/kid, expired, bad signature, HS256 confusion, nonce mismatch, unverified e-mail, token endpoint errors, RFC 9207 iss), state single use / wrong browser / wrong provider / garbage, open redirects, unreflected provider errors, GitHub (numeric id survives rename, verified primary e-mail required, 200-with-error, bad profile), linking policy, Alembic upgrade matches the models and downgrades cleanly, production settings guards.
- **Frontend**: `tsc --noEmit` clean, `next build` succeeds.
- **End-to-end smoke test through the Next.js proxy** (curl, real uvicorn + `next start` + redis-server, Secure cookies on localhost): register 201, `/me` 200, refresh 200 with rotation, dashboard 200, admin 403 for a user, old refresh token replayed after 11 s gives 401 `refresh_reuse_detected` and the live session then gets 401 `session_revoked`, cross-origin POST 403, nonce CSP present on pages.

**Not tested**: real Google/GitHub logins (no client credentials here, so providers were mocked at the HTTP layer), the Axios interceptors in a real browser (single flight, Web Locks, BroadcastChannel were type-checked and built but not run in a browser; there are no frontend unit or Playwright tests), Postgres (SQLite only), Redis Cluster, behaviour behind a real reverse proxy or HTTPS, and load.

## References used

RFC 6749 and RFC 7636 (OAuth 2.0, PKCE), RFC 9700 (OAuth 2.0 Security Best Current Practice: refresh-token rotation and reuse detection), RFC 9207 (`iss` on the authorization response), OpenID Connect Core (ID token validation), Google's "OpenID Connect" server-side flow docs, GitHub's OAuth app docs and its 2025 PKCE changelog, OWASP cheat sheets (CSRF, session management, password storage), and the Next.js 16 Content Security Policy guide shipped with the `next` package.
