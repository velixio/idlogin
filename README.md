# idlogin

A small, self-hosted sign-in service for [Zitadel](https://zitadel.com),
written in Go. It replaces Zitadel's bundled Login UI with server-rendered
pages for sign-in, sign-up, email codes, passwords, password reset, TOTP,
social login and logout, branded per hostname from one JSON file.

```
browser ──► app.example.com ──(OIDC redirect)──► id.example.com (nginx)
                                                   ├─ /login, /logout, /reset ──► idlogin :8091
                                                   └─ everything else ─────────► Zitadel :8090
idlogin ──(Zitadel v2 API, login-client token)──► Zitadel ──► PostgreSQL
```

## Why

- **Email-first, passwordless by default.** One screen asks for an email.
  People with a password get a password step; everyone else gets a 6-digit
  code. Unknown addresses can sign up by code, and the account is created
  only after the code is entered.
- **No JavaScript, no Node.** Go stdlib `net/http` and `html/template`, a
  strict CSP with no inline scripts, and one static binary with its assets
  embedded.
- **Several brands, one deployment.** Each brand is a Zitadel instance on its
  own hostname, with its own name, logo, sender address, login-client token,
  identity providers and registration policy.
- **Conservative security defaults.** Sealed cookies, CSRF tokens bound to
  the flow plus origin checks, allowlisted redirects only, server-side code
  attempt counters, per-IP and per-address rate limits, and the same neutral
  answer for "unknown address" and "disabled account".

## How it works with Zitadel

Zitadel stays the identity store and OIDC provider. Its `LoginV2` feature
sends browsers to idlogin with an auth request ID; idlogin checks the user
with the Zitadel v2 Session and User APIs (using the instance's
`IAM_LOGIN_CLIENT` token), then finalises the auth request and redirects back
to the app's callback. Codes are generated, stored (as HMACs) and checked by
idlogin in its own small PostgreSQL database and sent by its own mailer, so
email looks the same for every flow. Google, GitHub and generic OIDC
providers use Zitadel IdP intents. An optional Actions v2 target on a
loopback-only listener adds `email` and `email_verified` to JWT access tokens.

The full design, every flow and the security model are in
[docs/idlogin.md](docs/idlogin.md).

## Quick start (local)

Requirements: Go 1.26+, `curl`, and a local PostgreSQL you can administer
with `sudo -u postgres`. No containers.

```sh
git clone https://github.com/velixio/idlogin && cd idlogin
scripts/dev-up.sh       # downloads a pinned Zitadel release, creates the databases,
                        # builds and starts idlogin
open http://localhost:8090/ui/console   # signs in through idlogin as admin@id.localhost
scripts/dev-down.sh
```

State lives outside the repository in `IDLOGIN_DEV_HOME`
(default `${XDG_DATA_HOME:-$HOME/.local/share}/idlogin`): the Zitadel binary,
generated secrets (`secrets/local.env`, with the admin password), logs, pid
files, and dev mail (`mail/*.txt`, where the sign-in codes land).

## Configuration

Process settings are `LOGIN_*` environment variables
(`deploy/env/*.env.example`); brands are a JSON file (`LOGIN_BRANDS_FILE`,
reloaded on `SIGHUP`). A minimal brand:

```json
{
  "brands": [{
    "id": "example",
    "name": "Example",
    "hosts": ["id.example.com"],
    "public_origin": "https://id.example.com",
    "zitadel_host": "id.example.com",
    "logo_file": "logo.svg",
    "tagline": "Example keeps your account private.",
    "mail_from": "Example <no-reply@example.com>",
    "login_client_pat_file": "${CREDENTIALS_DIRECTORY}/login-client.pat",
    "return_urls": ["https://app.example.com/"],
    "registration_enabled": true,
    "idps": [{"key": "google", "id": ""}, {"key": "github", "id": ""}]
  }]
}
```

Everything a person sees that names the brand (page titles and headings,
logo, tagline, email sender and subjects) comes from this file; without a
`logo_file` a neutral built-in mark is shown. See
[docs/idlogin.md](docs/idlogin.md#configuration) for every variable and
field, and `deploy/brands.example.json` for a full example.

## Deploy

`deploy/` has generic, bare-metal files for one host:

| Path | What |
|---|---|
| `deploy/zitadel/{zitadel,production,local,steps}.yaml` | Zitadel config: base, production overlay (`id.example.com`), local overlay, first instance |
| `deploy/env/*.env.example` | Env templates with `REPLACE_ME` placeholders (the units refuse to start while one is left) |
| `deploy/systemd/{zitadel,idlogin}.service` | Hardened systemd units; idlogin gets its tokens as systemd credentials |
| `deploy/nginx/id.example.com.conf` | TLS, idlogin's paths to :8091, the rest to Zitadel over h2c |
| `deploy/postgres/create-db.sh` | Roles and databases for Zitadel and idlogin |
| `deploy/brands.example.json` | Brands file |

The steps are in [docs/idlogin.md](docs/idlogin.md#deploy-bare-metal-systemd).
Install the binary with `go install github.com/velixio/idlogin/cmd/idlogin@<tag>`
or build it from a checkout.

## Security model

- The login-client token can create a session for any user of its instance;
  treat it like a master password. Only the idlogin service should be able to
  read it (the unit loads it as a systemd credential).
- Flow state is in AEAD-sealed, HttpOnly, SameSite=Lax cookies (`__Host-` on
  HTTPS); anything replayable (code attempts, send counts, rate-limit
  windows) is in PostgreSQL.
- Every POST needs a CSRF token bound to the flow and must come from the
  brand's origin. Redirects go only to Zitadel's callback URLs or the brand's
  allowlisted return URLs.
- An auth request is never finalised with a session that lacks a verified
  factor, and `max_age` is enforced by idlogin.
- The action target listens on loopback only and checks Zitadel's signature
  on every call.

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## Limitations

- No passkeys / WebAuthn yet, neither registration nor sign-in.
- TOTP is verified when a user has it, but enrolling it (and other MFA
  management) happens in Zitadel, not in idlogin.
- No account picker: `prompt=select_account` behaves like `prompt=login`.
- OIDC only; SAML auth requests are not handled.
- English only, and one built-in dark theme (brand name, logo, tagline and
  email wording are configurable; the stylesheet is not).
- Tested against Zitadel v4.19.5; other versions may change the v2 API it
  uses.

## Development

```sh
go vet ./... && go test -race ./...
LOGIN_E2E=1 go test -count=1 -v ./internal/e2e   # against the running local stack
```

## License

Apache License 2.0, see [LICENSE](LICENSE). The embedded Geist and Fraunces
fonts are under the SIL Open Font License 1.1; see
[THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).
