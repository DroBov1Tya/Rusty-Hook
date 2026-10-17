# rusty_hook

Self-hosted webhook inspector, an alternative to webhook.site. Point any service at an
endpoint URL and watch the requests arrive in the browser in real time.

## Quick start

```sh
cp .env.example .env    # set ADMIN_KEY and POSTGRES_PASSWORD: openssl rand -hex 24
docker compose up -d --build
open http://localhost:8080
```

Create an endpoint in the panel, then:

```sh
curl -X POST 'http://localhost:8080/h/<endpoint-id>/any/path?x=1' \
  -H 'content-type: application/json' -d '{"hello":"world"}'
```

## Features

- `ANY /h/{uuid}[/*]` stores method, sub-path, query, headers and raw body.
- Live feed over SSE; the panel never polls.
- Per-endpoint response: status, content-type, body, delay up to 10 s.
- JSON view with highlighting that keeps key order and big numbers exact;
  form bodies as a table; binary bodies as base64.
- Copy as curl, filter, keyboard navigation (`j`/`k`, `n` new endpoint, `Esc`).
- Sign-in with an admin key and/or SSO through any OIDC provider; or an open panel.
- Retention: newest `MAX_REQUESTS_PER_ENDPOINT` per endpoint, `RETENTION_DAYS` max age.

## Architecture

```
  webhook senders           browser (panel)                  your IdP (optional)
        |                     |        ^                       ^
        | ANY /h/{uuid}/*     | /api/* | SSE /api/stream       | OIDC: discovery,
        v                     v        |                       | token, JWKS
  +------------------------------------------------------------+---------+
  | app  (axum, one static binary on scratch, uid 65534, read-only FS)   |
  |                                                                      |
  |  hook receiver --insert--> hook pool ---+                            |
  |        |                                 |                           |
  |        +--broadcast--> SSE hub           |      panel API --> panel pool
  |                                          v              |            |
  |  static files: Leptos WASM panel     Postgres <---------+            |
  +----------------------------------------------------------------------+
                                             |
                               internal network, no published port
```

| Component | Path | Role |
| --- | --- | --- |
| `shared` | `crates/shared` | API types and validation, compiled into both server and wasm |
| `server` | `crates/server` | Hook receiver, panel API, SSE, auth (key + OIDC), static files |
| `web` | `crates/web` | Leptos CSR panel built to wasm; `static/` holds html and css |
| schema | `init/init.sql` | Tables and constraints, applied on the first start of an empty volume |

Server layout: `main.rs` does global init only (allocator, logger, runtime) and hands over to
`app.rs`, which builds and runs the application; everything else hangs off `app/`:

```
crates/server/src/
  main.rs         global init -> app::Application::build(cfg)?.run()
  config.rs       env config + logger
  app.rs          Application: build() / run(), startup and shutdown
  app/
    storage.rs    Postgres pools, retention cleanup
    state.rs      shared AppState
    server.rs     accept loop (timeouts, connection cap), shutdown signal
    routes.rs     router, security headers, /healthz
    hooks.rs      public hook receiver /h/{id}
    api.rs        panel REST API + SSE
    auth.rs       sessions, key login, middleware
    auth/oidc.rs  SSO (OIDC)
    error.rs      RFC 9457 errors
    limits.rs     rate limits
    health.rs     `rusty-hook healthcheck` for Docker
```

## Configuration (.env)

| Variable | Default | Meaning |
| --- | --- | --- |
| `APP_PORT` / `APP_HOST` | `8080` / `0.0.0.0` | Published port and bind address on the host |
| `AUTH_MODE` | `login` | `login`: sign-in required; `open`: no login at all |
| `ADMIN_KEY` | empty | Key login, min 16 chars; empty disables the key form |
| `OIDC_ISSUER_URL` | empty | SSO issuer; empty disables SSO |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | - | Client registered at the IdP |
| `OIDC_REDIRECT_URL` | - | Exactly `https://<host>/api/oidc/callback`, as registered |
| `OIDC_ALLOWED_GROUPS` | - | IdP groups (`groups` claim) allowed in; recommended |
| `OIDC_ALLOWED_EMAILS` / `OIDC_ALLOWED_DOMAINS` | - | Exact match, only for emails the IdP marks verified |
| `OIDC_CA_FILE` | empty | Extra PEM root for an IdP behind a private CA |
| `OIDC_ALLOW_HTTP` | `false` | Allow `http://` issuer and redirect (local test IdPs only) |
| `COOKIE_SECURE` | `true` | `__Host-` Secure cookies; set `false` only for plain http |
| `SESSION_TTL_HOURS` | `24` | Session lifetime |
| `PUBLIC_HOSTS` | empty | Panel Host allowlist against DNS rebinding |
| `TRUST_FORWARDED` | `false` | Use the rightmost `X-Forwarded-For` entry (behind your own proxy only) |
| `MAX_BODY_BYTES` | `1048576` | Max captured body |
| `MAX_REQUESTS_PER_ENDPOINT` | `500` | Older requests are trimmed |
| `MAX_ENDPOINTS` | `100` | Endpoint cap |
| `MAX_CONNECTIONS` | `1024` | Open TCP connections |
| `HOOK_CONCURRENCY` | `64` | In-flight hooks; memory bound is this times `MAX_BODY_BYTES` |
| `HOOK_RATE_PER_MINUTE` | `600` | Per client IP; logins are fixed at 10/min per IP |
| `RETENTION_DAYS` | `7` | Max age of requests |
| `PG_MAX_CONNECTIONS` | `16` | Per pool (panel and hooks have one each) |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | - | Database credentials |

## SSO (OIDC)

Works with any OpenID Connect provider: Keycloak, Authentik, Zitadel, Google, Entra ID,
GitLab and others. Nothing extra runs in this stack.

Step-by-step guide for Authentik: [docs/sso-authentik.md](docs/sso-authentik.md).

1. At the IdP, create a confidential client with redirect URI
   `https://<your-host>/api/oidc/callback` and scopes `openid email profile`.
2. Fill `OIDC_*` in `.env` and at least one allowlist. Prefer `OIDC_ALLOWED_GROUPS`:
   groups are admin-managed, while emails count only with `email_verified=true`
   (Authentik 2025.10+ sends `false` by default).
3. `docker compose up -d`. The login page shows "Sign in with SSO"; the key form stays
   available if `ADMIN_KEY` is set.

The flow is authorization code with PKCE (S256), `state` bound to the browser by a
short-lived cookie, and `nonce`. The ID token signature, `iss`, `aud` and `exp` are
verified with the `openidconnect` crate.
Sessions are bound to the issuer and client, so changing either signs everyone out.
If the IdP is down, only SSO sign-in fails; hooks keep working.

## Security notes

- Hook responses carry `Content-Security-Policy: sandbox` and `nosniff`, so a user-defined
  HTML body cannot script the panel origin.
- Panel: strict CSP without inline scripts, `frame-ancestors 'none'`, HSTS,
  Fetch Metadata CSRF check, SameSite=Strict HttpOnly session cookie.
- Only the SHA-256 of session tokens is stored. Rotating `ADMIN_KEY` signs out key sessions.
- Captured data is rendered as text only; "Copy as curl" shell-quotes every part.
- Panel session cookies are stripped from captured headers before storage.
- 10 s header read timeout, connection cap, per-IP rate limits, bounded in-flight hooks,
  and separate DB pools so a hook flood cannot starve the panel.

## Limitations and honest caveats

- Hook URLs are public by design: the UUID is the capability. Anyone with the URL can post to it.
- The app connects as the Postgres owner role, not a DML-only role.
- Per-IP limits are weak against IPv6 address rotation; rate-limit `/h/*` at your proxy or CDN too.
- TLS is not terminated here. Put Caddy, Traefik or nginx in front and set `COOKIE_SECURE=true`.
- SSO was verified end to end against Authentik 2026.8.4 and a mock OIDC provider; other
  vendors should work but were not tested.
- Single instance: the live feed and pending SSO sign-ins live in process memory.
- An SSO session lasts `SESSION_TTL_HOURS` even if the user is removed from the allowed group
  in the IdP meanwhile; lower the TTL or restart with a changed client to cut sessions short.
- Behind a reverse proxy without `TRUST_FORWARDED=true`, all clients share the proxy IP and
  therefore one rate-limit bucket.

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p web --target wasm32-unknown-unknown -- -D warnings
docker compose up -d --build    # cached rebuild takes about a minute
```

Publish an image and deploy without building:

```sh
docker build -t <user>/rusty-hook:0.1.0 . && docker push <user>/rusty-hook:0.1.0
# .env: APP_IMAGE=<user>/rusty-hook:0.1.0, then: docker compose up -d
```

## License

MIT, see [LICENSE](LICENSE).
