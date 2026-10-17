# Rusty Hook

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
    api.rs        panel API: endpoints.rs, requests.rs, stream.rs (SSE) in api/
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
