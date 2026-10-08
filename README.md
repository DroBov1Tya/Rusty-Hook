# rusty_hook

Self-hosted webhook inspector (webhook.site alternative).
Rust (axum) backend, Rust -> WASM (Leptos) panel, PostgreSQL storage.
One ~10 MB `scratch` image with a static binary, plus Postgres.

## Quick start

```sh
cp .env.example .env        # fill ADMIN_KEY / POSTGRES_PASSWORD (openssl rand -hex 24)
docker compose up -d --build
open http://localhost:8080  # APP_PORT in .env
```

Send something:

```sh
curl -X POST http://localhost:8080/h/<endpoint-id>/any/path?x=1 \
  -H 'content-type: application/json' -d '{"hello":"world"}'
```

## Features

- Endpoints `ANY /h/{uuid}[/*]`: every method, sub-path, query, headers and raw body are stored.
- Live feed over SSE, no polling.
- Configurable response per endpoint: status, content-type, body, delay.
- JSON pretty view with highlighting (key order and big numbers kept), form-urlencoded as a table, binary as base64.
- Copy as curl, filter, keyboard: `j`/`k` navigate, `n` new endpoint, `Esc` close.
- Retention: last `MAX_REQUESTS_PER_ENDPOINT` per endpoint and `RETENTION_DAYS` max age.

## Layout

```
crates/shared   API types + validation (used by both sides)
crates/server   axum: API, hook receiver, static files, auth
crates/web      Leptos CSR panel -> wasm (static/ has index.html, css)
init/init.sql   DB schema, applied on first start of an empty volume
```

## Configuration (.env)

| Var | Default | Meaning |
| --- | --- | --- |
| `APP_PORT` / `APP_HOST` | `8080` / `0.0.0.0` | Published port / bind address on host |
| `AUTH_MODE` | `key` | `key` = login with `ADMIN_KEY`; `open` = no login (explicit opt-in) |
| `ADMIN_KEY` | - | Panel key, min 16 chars (required in `key` mode) |
| `PUBLIC_HOSTS` | empty | Panel Host allowlist (DNS rebinding guard), e.g. `hooks.example.com,localhost` |
| `COOKIE_SECURE` | `true` (code) | `true` behind HTTPS (`__Host-` cookie); `false` for plain http |
| `SESSION_TTL_HOURS` | `24` | Session lifetime |
| `TRUST_FORWARDED` | `false` | Use rightmost `X-Forwarded-For` entry as client IP (only behind your proxy) |
| `MAX_BODY_BYTES` | `1048576` | Max captured body |
| `MAX_REQUESTS_PER_ENDPOINT` | `500` | Older requests are trimmed |
| `MAX_ENDPOINTS` | `100` | Cap on endpoints |
| `MAX_CONNECTIONS` | `1024` | Open TCP connections |
| `HOOK_CONCURRENCY` | `64` | In-flight hooks (memory bound = this x `MAX_BODY_BYTES`) |
| `HOOK_RATE_PER_MINUTE` | `600` | Per client IP; login is fixed at 10/min per IP |
| `RETENTION_DAYS` | `7` | Max age of requests |
| `POSTGRES_USER/PASSWORD/DB` | - | Database credentials |

## Auth modes

1. **Admin key** (default, `AUTH_MODE=key`): login form, opaque session cookie
   (HttpOnly, SameSite=Strict). Only the SHA-256 of the token is stored; sessions are bound
   to the current key, so rotating `ADMIN_KEY` logs everyone out.
2. **Open** (`AUTH_MODE=open`, `ADMIN_KEY=` empty): no login. Use only on trusted networks
   and set `PUBLIC_HOSTS` to block DNS rebinding.

Hook URLs `/h/*` are always public by design: the UUID is the capability.

## Security notes

- Hook responses carry `Content-Security-Policy: sandbox` and `nosniff`, so a user-defined
  HTML body can't script the panel origin.
- Panel: strict CSP (no inline JS), `frame-ancestors 'none'`, HSTS, Fetch-Metadata CSRF check.
- Captured data is rendered as text only (no `innerHTML`); "Copy as curl" shell-quotes every part.
- Panel session cookies are stripped from captured headers before storage.
- Slowloris guard (10 s header read timeout), connection cap, per-IP rate limits,
  bounded in-flight hooks, separate DB pool for hooks so floods can't starve the panel.
- Containers: app runs as uid 65534 on a read-only FS, all capabilities dropped, memory/pids limits;
  Postgres sits on an internal network without a published port.
- Known gap: the app connects as the Postgres owner role (see "Hardening" below).
- Put TLS in front (Caddy/Traefik/nginx) for anything non-local and set `COOKIE_SECURE=true`.

## Develop

```sh
cargo test --workspace
cargo clippy --workspace --all-targets
cargo check -p web --target wasm32-unknown-unknown
docker compose up -d --build   # rebuild after changes (cached, ~1 min)
```

## Publish to Docker Hub

```sh
docker build -t <user>/rusty-hook:0.1.0 .
docker push <user>/rusty-hook:0.1.0
# then in .env: APP_IMAGE=<user>/rusty-hook:0.1.0 and `docker compose up -d` (no --build)
```

## Hardening (optional)

- Dedicated DML-only DB role for the app instead of `POSTGRES_USER`.
- Pin base images by digest; run `cargo audit` / `cargo deny` in CI.
- Behind a CDN or proxy, also rate-limit `/h/*` there (IPv6 makes per-IP limits weaker).
