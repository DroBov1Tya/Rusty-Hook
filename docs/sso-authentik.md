# SSO with Authentik

Step-by-step setup of rusty_hook sign-in through [Authentik](https://goauthentik.io).
Checked against Authentik 2026.8.4. Other OIDC providers work the same way; only the
IdP-side screens differ.

Access is granted by **Authentik group**. This matters: since Authentik 2025.10 the
`email_verified` claim defaults to `false`, and rusty_hook only trusts emails the IdP
marks as verified. Groups are managed by admins, so they are the reliable signal.

## What you need

- Authentik reachable over HTTPS from the browser **and** from the rusty_hook container,
  under the same hostname (example below: `https://auth.example.com`).
- The public URL of rusty_hook (example: `https://hooks.example.com`).

## 1. Group

Admin interface -> **Directory -> Groups -> Create**:

- Name: `rusty-hook-users`
- Then open the group -> **Users** -> add everyone who should see the panel.

## 2. Application and provider

Admin interface -> **Applications -> Applications -> Create with provider**.

Application:

| Field | Value |
| --- | --- |
| Name | `rusty_hook` |
| Slug | `rusty-hook` (becomes part of the issuer URL) |

Provider type: **OAuth2/OpenID Provider**. Provider settings:

| Field | Value |
| --- | --- |
| Authorization flow | `default-provider-authorization-implicit-consent` (or explicit consent) |
| Client type | **Confidential** |
| Client ID / Client Secret | keep the generated values, you need them in step 3 |
| Redirect URIs | **Strict**: `https://hooks.example.com/api/oidc/callback` |
| Signing Key | `authentik Self-signed Certificate` (any RSA/EC key; must not be empty) |
| Grant Types | leave **only Authorization Code** checked (the form pre-checks more) |
| Scopes (advanced) | keep the defaults: `openid`, `email`, `profile` |

Recommended, defense in depth: on the application page -> **Policy / Group / User
Bindings -> Bind existing group** -> `rusty-hook-users`. Then Authentik itself refuses
everyone else before they reach rusty_hook.

## 3. rusty_hook configuration

In `.env`:

```sh
OIDC_ISSUER_URL=https://auth.example.com/application/o/rusty-hook/
OIDC_CLIENT_ID=<client id from step 2>
OIDC_CLIENT_SECRET=<client secret from step 2>
OIDC_REDIRECT_URL=https://hooks.example.com/api/oidc/callback
OIDC_ALLOWED_GROUPS=rusty-hook-users
COOKIE_SECURE=true
```

The issuer must match Authentik exactly, **including the trailing slash**. Copy it from:

```sh
curl -s https://auth.example.com/application/o/rusty-hook/.well-known/openid-configuration | grep -o '"issuer": *"[^"]*"'
```

Keep `ADMIN_KEY` set if you want a fallback login, or clear it for SSO only.

### Authentik behind a private or self-signed CA

Give rusty_hook the CA certificate (PEM). Create `docker-compose.override.yml` next to
`docker-compose.yml` (compose picks it up automatically):

```yaml
services:
  app:
    volumes:
      - ./certs/idp-ca.pem:/certs/idp-ca.pem:ro
```

and set `OIDC_CA_FILE=/certs/idp-ca.pem` in `.env`. The public web roots stay trusted too.

## 4. Start and check

```sh
docker compose up -d
docker compose logs app | grep oidc
# expect: INFO oidc provider discovered
```

Open the panel: the login page shows **Sign in with SSO**. Every attempt is written to
the app log as `audit="login_ok" method="sso"` or `audit="sso_failed" reason=...`.

## Troubleshooting

| Log line | Cause | Fix |
| --- | --- | --- |
| `discovery: Validation error: unexpected issuer URI` | Issuer differs, usually the trailing `/` | Copy `issuer` from the discovery document |
| `discovery: Request failed` | DNS, network or TLS from the container | Check the hostname from inside Docker; private CA -> `OIDC_CA_FILE` |
| `reason=idp error "invalid_request"` and Authentik logs `Invalid grant_type for provider` | Authorization Code grant is not enabled | Provider -> Grant Types -> check Authorization Code |
| Authentik shows a redirect URI error | Redirect URI does not match exactly | Make it identical to `OIDC_REDIRECT_URL`, mode Strict |
| `reason=account no allowed group and email not verified` | User is not in an allowed group | Add the user to `rusty-hook-users`, or fix `OIDC_ALLOWED_GROUPS` |
| `reason=id_token: Invalid audiences` | Client ID mismatch | Use the Client ID of this provider |
| `reason=missing flow cookie` or `state mismatch` | Cookie lost between start and callback | Same hostname for start and callback; `COOKIE_SECURE=true` needs HTTPS |
