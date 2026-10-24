# idlogin: design and operations

idlogin is a sign-in service for [Zitadel](https://zitadel.com). It serves
every browser screen people see when they sign in, sign up, enter an email
code, enter a password or reset it, and it replaces Zitadel's bundled Login UI
(tested against Zitadel v4.19.5). Zitadel stays the identity store and the
OIDC provider; idlogin drives it through the Zitadel v2 API (Sessions, Users,
OIDC auth requests, IdP intents) with the instance's login-client token (role
`IAM_LOGIN_CLIENT`). Operators keep using Zitadel's console at `/ui/console`,
and it signs them in through idlogin like any other app.

It is Go stdlib `net/http` + `html/template`, with `pgx/v5` for its own small
PostgreSQL database. No JavaScript is needed; `static/app.js` only adds
show/hide buttons for passwords.

Zitadel is configured to send browsers to idlogin
(`deploy/zitadel/zitadel.yaml`):

- `LoginV2.BaseURI` = idlogin's origin (locally `http://localhost:8091`, in
  production the instance domain, e.g. `https://id.example.com`, where nginx
  routes idlogin's paths to it).
- `OIDC.DefaultLoginURLV2` = `/login?authRequest=` and
  `OIDC.DefaultLogoutURLV2` = `/logout?post_logout_redirect=`. (With
  `BaseURI` set, Zitadel builds `BaseURI + /login` and `BaseURI + /logout`;
  the defaults are only a fallback.)

## Credentials and what they allow

- **Login-client token** (`IAM_LOGIN_CLIENT`, the brand's
  `login_client_pat_file`). It can create a session for any user of the
  instance, so holding it is equivalent to signing in as anyone. Only the
  idlogin service may read it; the systemd unit receives it as a credential
  (`LoadCredential=`) from Zitadel's state directory.
- **Action-target signing key** (`LOGIN_ACTIONS_SIGNING_KEY_FILE`). Zitadel
  signs its Actions v2 `preaccesstoken` calls with it, and idlogin's
  loopback-only target checks the signature before it adds
  `email`/`email_verified` to JWT access tokens. It cannot mint tokens or
  sessions, but relying parties may trust those claims, so it is also handed
  only to the idlogin service, as a credential.
- **Provisioner token** (an IAM owner). Used only by `idlogin setup`, run by
  an operator; the running service never needs it.
- **Cookie key** (`LOGIN_COOKIE_KEY`). Seals flow cookies and keys the code
  HMACs. Rotating it ends every pending flow.

## Layout

| Path | What |
|---|---|
| `cmd/idlogin` | The binary: `idlogin` serves; `idlogin setup` does the instance setup |
| `internal/web` | Routes, flows, CSRF/origin checks, sealed cookies, templates, static assets (embedded) |
| `internal/zitadel` | JSON client for the v2 API (sessions, users, OIDC auth requests, IdP intents, settings) |
| `internal/store` | PostgreSQL store (codes + attempt counters, rate-limit windows) with embedded migrations; memory store for tests |
| `internal/seal` | AES-256-GCM sealed cookie values, bound to the cookie name, with expiry |
| `internal/mailer` | SMTP mailer and the `log` dev mailer (`.eml` + `.txt` per message) |
| `internal/actions` | Zitadel Actions v2 target `preaccesstoken` (email claims in JWT access tokens) |
| `internal/setup` | Idempotent instance setup: action target + execution, OIDC token lifetimes |
| `internal/config` | Env config and the brands file |
| `internal/e2e` | End-to-end test against the local stack (`LOGIN_E2E=1`) |
| `deploy/brands.example.json` | Brands file example |
| `deploy/env/*.env.example` | Env templates (local, Zitadel production, idlogin production) |
| `deploy/zitadel/*.yaml` | Zitadel runtime config, production and local overlays, first-instance steps |
| `deploy/systemd/*.service`, `deploy/nginx/id.example.com.conf` | Units and nginx server block |
| `deploy/postgres/create-db.sh` | Creates the `zitadel` and `idlogin` roles and databases |
| `scripts/` | `install.sh` (pinned Zitadel release), `dev-up.sh`, `dev-down.sh` |

idlogin has its own `idlogin` database and role (created by
`deploy/postgres/create-db.sh`), separate from Zitadel's and from any
product's. Its migration (`internal/store/migrations/`) is embedded in the
binary and applied at start.

## Flows

- **One email-first screen.** "Sign in or create your account", with an
  optional "Keep me signed in for 30 days" box (session lifetime 7 days by
  default, 30 when ticked) and Google/GitHub (or any other configured IdP)
  buttons.
- **Existing active user with a password.** A password step with a "Forgot
  password?" link and an "Email me a code instead" button.
- **Existing active user without a password.** A code is emailed at once.
- **Unknown email, registration open.** A code is emailed. The account is
  created only after the code succeeds: email verified, no password, and the
  email-code factor added. Then the user is signed in.
- **Unknown email with registration closed, or a disabled/locked user.** The
  same neutral "this address can't be used to sign in" answer. No code is sent
  and no user is created, and the two cases cannot be told apart.
- **Code rules.** 6 digits, valid for 10 minutes, single use. A code dies
  after 5 wrong attempts. At most 5 codes per address per hour; "Send a new
  code" counts toward that.
- **TOTP.** If the user has an authenticator app set up, it is required after
  the first factor.
- **Password reset.** Email → code → new password, then signed in. It works
  inside an auth request, or standalone at `/reset?return=<allowlisted URL>`
  for "change password" links from products.
- **Google / GitHub / generic OIDC.** Zitadel IdP intents. When the provider
  says the email is verified, the identity is linked to the existing user with
  that email. Otherwise the user is created if registration is open.
- **SSO.** If a valid session already exists in this browser and
  `prompt`/`max_age` allow it, the auth request is finalised without asking
  again.
  - `prompt=login` forces re-authentication (step-up).
  - `prompt=none` returns `login_required` instead of showing a page.
  - `prompt=create` opens in sign-up mode.
- **Logout.** End-session lands on `/logout`. It terminates this browser's
  Zitadel sessions, then continues to the post-logout redirect.

## Security model

- Flow state lives in an AEAD-sealed, HttpOnly, SameSite=Lax cookie, with the
  `__Host-` prefix on HTTPS. Anything that must not be replayable (code
  attempts, send counts) is stored server-side in PostgreSQL.
- CSRF: every POST carries a token bound to the flow cookie, and requests
  must come from the brand's public origin.
- Redirects go only to a `callbackUrl` returned by Zitadel, or to the brand's
  allowlisted return URLs. Nothing else.
- Strict CSP (`default-src 'none'`, `'self'` scripts, styles, images and
  fonts), `frame-ancestors 'none'`, no inline scripts. There is no
  `form-action`: browsers apply it to the redirect after a POST, which goes to
  app callback URLs.
- Per-IP and per-address rate limits on code sends, lookups, code checks and
  password and TOTP attempts.
- Each brand (Zitadel instance) has its own public host, login-client token
  and branding. Calls to Zitadel carry that host so the right instance
  answers.
- The action target is served on the public listener at
  `/login/zitadel/preaccesstoken` and Zitadel calls it through the public
  hostname, so Zitadel's SSRF deny list (`deploy/zitadel/zitadel.yaml`) has
  no exceptions: no loopback or private address, IPv4 or IPv6, is allowed. Every call must carry Zitadel's signature; a
  valid call only returns the email claims for the user in its own payload.
  Do not carve exceptions into the deny list: it has no per-port rules, so
  allowing one address exposes every service on the host that listens on
  `0.0.0.0`. The public hostname must resolve to a public address for
  Zitadel (split-horizon DNS to a private address would be blocked).

## Email

idlogin sends its own branded email: codes for sign-in, sign-up, email
verification and password reset. Zitadel's built-in notifications are not
used for these. In development the `log` mailer writes each message to
`LOGIN_MAIL_DIR` (`.eml` and `.txt`), so tests and people can read codes
without SMTP.

## Implementation notes

- **Codes are idlogin's.** Every code is generated, stored (HMAC only) and
  checked by idlogin in PostgreSQL; Zitadel never mails or checks them. A
  Zitadel session still needs a verified factor, so after a code succeeds the
  user gets Zitadel's email-OTP factor and the session's OTP-email challenge
  is requested with `returnCode` and answered at once. Zitadel's
  `SecretGenerators.OTPEmail` therefore does not matter.
- **Reset** uses an idlogin code too; on success idlogin asks Zitadel for a
  reset code with `returnCode`, sets the password with it, then signs the user
  in with the new password. Unknown or unusable addresses get a code that is
  stored but never sent, so the pages look the same.
- **New users** (code sign-up or IdP): username and email = the address,
  given and family name = the local part (Zitadel requires both), display name
  = the local part (or the IdP's profile), no password.
- **Never finalise without a factor.** Zitadel would finalise an auth request
  with a session that only has a user check. idlogin only links sessions with
  a password, passkey, IdP or email-code factor (plus TOTP when the user has
  it), and checks `max_age` itself.
- **Accounts are found by current email only.** The typed address is matched
  against each account's current email, never its login name: after an email
  change the login name can still be the old address, and a code sent there
  would give the account to whoever controls the old inbox.
- **TOTP is bound to the account.** A passed TOTP check is recorded for one
  user and one Zitadel session; switching the flow to another account (for
  example through a password reset) always asks for that account's TOTP.
- **Unverified email.** If the account's email is unverified at sign-in (for
  example after an operator changed it), an email code to that address is
  required before the auth request is finalised; the email is then marked
  verified.
- **Remember me.** Session lifetime 7 days, 30 when ticked; when ticked,
  `remember_me=1` is appended to the callback URL (also on SSO reuse of a
  remembered session) so products can match their own session length.
- **SSO.** A sealed `idl-sessions` cookie keeps up to 5 of this browser's
  Zitadel sessions. `prompt=select_account` is treated like `prompt=login`
  (there is no account picker). Requests from **native** OIDC apps never reuse
  the browser's sessions and their new session is not added to the cookie, so
  a web logout does not end desktop tokens.
- **Logout.** With `id_token_hint`, Zitadel ends that session itself and never
  shows `/logout`. Without it, Zitadel sends the browser to
  `/logout?post_logout_redirect=…&logout_token=<JWT>`; a logout token signed
  by the instance keys ends this browser's sessions immediately and continues
  to its `post_logout_redirect_uri`. Without a valid token the page asks for
  confirmation and only redirects to allowlisted URLs. Ending sessions makes
  Zitadel send back-channel logouts to the apps.
- **IdP intents.** The success URL carries a random state bound to the flow
  cookie. Linked identity → that user; provider-verified email matching one
  account → link and sign in; no account and a provider-verified email →
  create it (registration open); anything else, including any unverified
  provider email, → the neutral error. An unverified email never links or
  creates: otherwise someone could pre-create an account under another
  person's address with their own provider login attached.
- **Limits** (per brand): 5 codes per address per hour, 30 per IP per hour;
  5 attempts per code; password 10 per account and 50 per IP per 15 minutes;
  60 email lookups and 60 code checks per IP per 15 minutes; TOTP 10 per
  account per 15 minutes.
- **Access-token claims.** The action target for `function/preaccesstoken`
  adds `email` and `email_verified` to JWT access tokens. `idlogin setup`
  creates the target and execution and applies the OIDC token lifetimes.

## Routes

Public (nginx sends these to `127.0.0.1:8091`; none collides with Zitadel's
own routes):

| Path | |
|---|---|
| `GET /login?authRequest=V2_…` | Entry from Zitadel: prompt/max_age, SSO reuse, else the email page |
| `GET,POST /login/email` | Email-first step (remember-me, IdP buttons) |
| `GET,POST /login/password` | Password step (or "Email me a code instead") |
| `GET,POST /login/code` | Email code (sign-in, sign-up, email verification), resend |
| `GET,POST /login/totp` | Authenticator code |
| `POST /login/restart` | "Use a different email" |
| `POST /login/idp`, `GET /login/idp/callback`, `GET /login/idp/failure` | IdP intents |
| `GET,POST /reset`, `GET,POST /reset/code` | Password reset (in an auth request, or `/reset?return=<allowlisted URL>`) |
| `GET,POST /logout`, `GET /logout/done` | Zitadel's end-session landing page |
| `GET /login/brand/logo` | The request's brand logo (its `logo_file`, or the built-in mark) |
| `GET /login/static/…`, `GET /login/healthz` | Assets, health |

Called by Zitadel only, enabled by `LOGIN_ACTIONS_SIGNING_KEY_FILE`:
`POST /login/zitadel/preaccesstoken` (ZITADEL-Signature required).

## Configuration

Environment (`deploy/env/local.env.example`,
`deploy/env/idlogin.production.env.example`):

| Variable | Default | Meaning |
|---|---|---|
| `LOGIN_ADDR` | `127.0.0.1:8091` | Public listener (behind nginx in production) |
| `LOGIN_ZITADEL_URL` | `http://127.0.0.1:8090` | Zitadel API base URL |
| `LOGIN_BRANDS_FILE` | required | Brands JSON (below). `SIGHUP` reloads it, logos included |
| `LOGIN_DATABASE_URL` | required | e.g. `postgres://idlogin@127.0.0.1:5432/idlogin?sslmode=disable` |
| `LOGIN_DATABASE_PASSWORD` | | Overrides the URL's password; also read by `deploy/postgres/create-db.sh` |
| `LOGIN_COOKIE_KEY` | required | base64 of 32 bytes. Cookie sealing and code HMAC keys are derived from it |
| `LOGIN_MAILER` | `log` | `log` (files in `LOGIN_MAIL_DIR`) or `smtp` |
| `LOGIN_MAIL_DIR` | | Dev mail directory |
| `LOGIN_SMTP_HOST`, `_PORT`, `_USER`, `_PASSWORD`, `_TLS` | port 587, `starttls` | SMTP; `_TLS` is `starttls`, `tls` (465) or `none` |
| `LOGIN_TRUST_PROXY` | `false` | Take the client IP (rate limits) from the last `X-Forwarded-For` hop |
| `LOGIN_ACTIONS_SIGNING_KEY_FILE` | | Target signing key (written by `idlogin setup`, re-read per call) |
| `LOGIN_LOG_LEVEL` | `info` | `debug` for more |

### Brands

One entry per brand (Zitadel instance), selected by the request's `Host`.
Example: `deploy/brands.example.json`; `scripts/dev-up.sh` writes
`$IDLOGIN_DEV_HOME/idlogin/brands.json` for local use. `${VAR}` is expanded
from the environment; relative token and logo paths are relative to the
file. Unknown fields are rejected.

| Field | |
|---|---|
| `id`, `name` | Brand key (rate-limit and code scoping) and the display name used in titles, headings and email |
| `hosts` | `Host` values served, e.g. `id.example.com` |
| `public_origin` | idlogin's origin as browsers see it; POSTs must come from it; `https` turns on `__Host-` cookies and HSTS |
| `zitadel_host` | Sent as `x-zitadel-instance-host` and `x-zitadel-public-host` so the right instance answers |
| `logo_file` | Logo (`.svg`, `.png`, `.webp` or `.ico`, at most 256 KiB), read when the file is loaded and served at `/login/brand/logo`. Empty: a neutral built-in mark |
| `tagline` | Optional small line under the card |
| `mail_from` | `From` of code and reset mail, e.g. `Example <no-reply@example.com>` |
| `mail_subjects` | Optional subjects per email kind: `signin`, `signup`, `reset`, `verify`; `{name}` is replaced by `name` |
| `login_client_pat_file` | The instance's `IAM_LOGIN_CLIENT` token |
| `return_urls` | Allowlisted return URL prefixes (scheme, host, port exact; path segment prefix) for `/reset?return=` and logout |
| `registration_enabled` | Unknown addresses may sign up (by code, or via an IdP) |
| `org_id` | Organization for new users; empty = the login client's organization |
| `idps` | `[{key, id, label}]`; a button appears when `id` (a Zitadel IdP ID) is set. `google`/`github` get icons |

The look is a dark theme (`internal/web/static/app.css`) with the Geist and
Fraunces fonts; change the stylesheet in a fork if you need another one.

## Running locally

Needs Go, `curl`, and a local PostgreSQL you can administer with
`sudo -u postgres`.

```sh
scripts/dev-up.sh      # Zitadel :8090, idlogin :8091
scripts/dev-down.sh
```

State (the Zitadel binary, secrets, logs, dev mail, pid files) lives in
`IDLOGIN_DEV_HOME`, default `${XDG_DATA_HOME:-$HOME/.local/share}/idlogin`,
outside the repository. The first run downloads the pinned Zitadel release
(checksum-verified), generates secrets into `secrets/local.env`, creates the
two databases and initialises the instance. Every run builds
`$IDLOGIN_DEV_HOME/bin/idlogin` from this checkout, runs `idlogin setup`, and
(re)starts it. Codes land in `$IDLOGIN_DEV_HOME/mail/<time>-<kind>-<address>.txt`;
logs in `$IDLOGIN_DEV_HOME/log/`. The console is at
<http://localhost:8090/ui/console> as `admin@id.localhost` (password
`ZITADEL_FIRSTINSTANCE_ORG_HUMAN_PASSWORD` in `secrets/local.env`).

`idlogin setup -pat-file <IAM owner PAT> [-zitadel URL] [-instance-host HOST]
[-actions-endpoint URL -actions-key-file FILE] [-oidc-settings=true]` applies:

- OIDC token lifetimes on the instance (access 5m, ID 1h, refresh idle 720h,
  refresh 2160h; the same values are `DefaultInstance.OIDCSettings` for new
  instances);
- the action target `idlogin-preaccesstoken` (REST call, JSON payload, 5s,
  not interrupting on error) and the execution `function/preaccesstoken`. The
  signing key Zitadel returns is written to the key file; delete the file and
  re-run to rotate it.

## Deploy (bare metal, systemd)

1. Zitadel: `PREFIX=/opt/zitadel scripts/install.sh`; copy
   `deploy/zitadel/{zitadel,production,steps}.yaml` to `/etc/zitadel/`
   (replace `id.example.com` and the "Example" names);
   `/etc/zitadel/zitadel.env` from `deploy/env/production.env.example`.
2. Databases: `ZITADEL_DB_PASSWORD=... LOGIN_DATABASE_PASSWORD=...
   deploy/postgres/create-db.sh`.
3. `deploy/systemd/zitadel.service`, `systemctl enable --now zitadel`. The
   first start writes `login-client.pat` and `provisioner.pat` to
   `/var/lib/zitadel/`.
4. idlogin: `CGO_ENABLED=0 go build -trimpath -o /usr/local/bin/idlogin
   ./cmd/idlogin` (or `go install github.com/velixio/idlogin/cmd/idlogin@<tag>`).
5. `/etc/idlogin/idlogin.env` from `deploy/env/idlogin.production.env.example`,
   `/etc/idlogin/brands.json` from `deploy/brands.example.json`, and the logo
   it names.
6. `idlogin setup -zitadel http://127.0.0.1:8090 -instance-host id.example.com
   -pat-file /var/lib/zitadel/provisioner.pat -actions-endpoint
   https://id.example.com/login/zitadel/preaccesstoken -actions-key-file
   /etc/idlogin/actions.key` (as root; the key file stays root-only and
   reaches the service as a systemd credential).
7. `deploy/systemd/idlogin.service`, `systemctl enable --now idlogin`.
   `systemctl reload idlogin` re-reads brands.json and logos; restart after
   rotating a token or key.
8. nginx: `deploy/nginx/id.example.com.conf` (TLS, idlogin's paths to :8091,
   everything else to Zitadel over h2c).

## Testing

```sh
go vet ./... && go test -race ./...
# also run the store tests against PostgreSQL:
LOGIN_TEST_DATABASE_URL=postgres://idlogin:<pw>@127.0.0.1:5432/idlogin?sslmode=disable go test -race ./internal/store
# end to end, against the running local stack:
LOGIN_E2E=1 go test -count=1 -v ./internal/e2e
```

Unit tests (`internal/web`) run every flow against a fake Zitadel: sign-up by
code, password, passwordless, password→code, TOTP, unverified email, reset (in
a flow and standalone), IdP link/create/refuse, SSO reuse, prompt
none/login/create, max_age, login_hint, native apps, logout with and without a
signed logout token, brand logos and mail subjects; and the rules: CSRF token
and origin, open redirects, send / password / attempt limits, code expiry,
identical neutral errors, security headers. `internal/store` checks atomic
attempt counting under parallel guesses.

The e2e test reads the stack's state from `IDLOGIN_DEV_HOME` (secrets, pid
file, brands file). It runs a minimal relying party in the test process on
:8095 (code flow + PKCE, RP-initiated and back-channel logout), and creates
fixture users (deleted afterwards) and a fixture project `idlogin-e2e` with
the relying party's web app, a native JWT app and the client of a generic OIDC
IdP `e2e-loopback` that points at the same Zitadel. It temporarily adds that
IdP plus a registration-closed brand on `127.0.0.1:8091` to the brands file
(SIGHUP, restored afterwards), and clears the per-IP rate-limit windows for
loopback first so it can be repeated.
