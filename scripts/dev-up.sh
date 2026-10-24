#!/bin/sh
# Runs Zitadel + idlogin (cmd/idlogin, built from this checkout) locally
# without containers, against the local PostgreSQL. First run generates
# secrets, creates the zitadel and idlogin databases (sudo -u postgres) and
# initialises the instance; later runs start Zitadel if needed and (re)build
# and restart idlogin.
#
#   scripts/dev-up.sh     then open http://localhost:8090/ui/console
#   scripts/dev-down.sh
#
# All local state (Zitadel binary, secrets, logs, dev mail, pid files) lives in
# IDLOGIN_DEV_HOME, outside the repository, so every checkout shares one
# stack. Default: ${XDG_DATA_HOME:-$HOME/.local/share}/idlogin.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN="${IDLOGIN_DEV_HOME:-${XDG_DATA_HOME:-$HOME/.local/share}/idlogin}"
export IDLOGIN_DEV_HOME="$RUN"
CONF="$ROOT/deploy/zitadel"
SECRETS="$RUN/secrets"
ENV="$SECRETS/local.env"
mkdir -p "$SECRETS" "$RUN/log" "$RUN/idlogin" "$RUN/bin" "$RUN/mail"
chmod 700 "$SECRETS"

[ -x "$RUN/zitadel/zitadel" ] || PREFIX="$RUN" "$ROOT/scripts/install.sh"

rand() { head -c 64 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c "$1"; }
key32() { head -c 32 /dev/urandom | base64 | tr -d '\n'; }

# fill_login FILE: fills the idlogin values of a copied env section.
fill_login() {
  sed -e "s#^LOGIN_DATABASE_PASSWORD=.*#LOGIN_DATABASE_PASSWORD=$logindb#" \
      -e "s#^LOGIN_COOKIE_KEY=.*#LOGIN_COOKIE_KEY=$(key32)#" \
      -e "s#@IDLOGIN_DEV_HOME@#$RUN#g" "$1"
}

if [ ! -f "$ENV" ]; then
  dbpw="$(rand 32)"
  logindb="$(rand 32)"
  sed -e "s#^ZITADEL_MASTERKEY=.*#ZITADEL_MASTERKEY=$(rand 32)#" \
      -e "s#^ZITADEL_DATABASE_POSTGRES_USER_PASSWORD=.*#ZITADEL_DATABASE_POSTGRES_USER_PASSWORD=$dbpw#" \
      -e "s#^ZITADEL_DATABASE_POSTGRES_ADMIN_PASSWORD=.*#ZITADEL_DATABASE_POSTGRES_ADMIN_PASSWORD=$dbpw#" \
      -e "s#^ZITADEL_FIRSTINSTANCE_ORG_HUMAN_PASSWORD=.*#ZITADEL_FIRSTINSTANCE_ORG_HUMAN_PASSWORD=Aa1!$(rand 20)#" \
      -e "s#@IDLOGIN_DEV_HOME@#$RUN#g" \
      "$ROOT/deploy/env/local.env.example" > "$ENV.tmp"
  fill_login "$ENV.tmp" > "$ENV"
  rm -f "$ENV.tmp"
  chmod 600 "$ENV"
  ZITADEL_DB_PASSWORD="$dbpw" LOGIN_DATABASE_PASSWORD="$logindb" "$ROOT/deploy/postgres/create-db.sh"
fi

set -a; . "$ENV"; set +a

# LOGIN_ACTIONS_ADDR is retired (the action target moved onto LOGIN_ADDR).
sed -i '/^LOGIN_ACTIONS_ADDR=/d;/^# Loopback listener for the Zitadel action target/d' "$ENV"
unset LOGIN_ACTIONS_ADDR

# Every path in local.env must point into this home (a copied local.env that
# still names another state directory would mix two stacks).
for v in "$ZITADEL_FIRSTINSTANCE_PATPATH" "$LOGIN_BRANDS_FILE" "$LOGIN_MAIL_DIR" "$LOGIN_ACTIONS_SIGNING_KEY_FILE"; do
  case "$v" in
    "$RUN"/*) ;;
    *) echo "$ENV names $v, outside $RUN; fix the path" >&2; exit 1 ;;
  esac
done

running() { [ -f "$RUN/$1.pid" ] && kill -0 "$(cat "$RUN/$1.pid")" 2>/dev/null; }

if ! running zitadel; then
  # The role and database already exist (create-db.sh), and the role is not
  # allowed to create databases, so only initialise Zitadel's own schemas.
  # Both this and setup skip work that is already done.
  "$RUN/zitadel/zitadel" init zitadel \
    --config "$CONF/zitadel.yaml" >>"$RUN/log/zitadel.log" 2>&1 || {
    echo "zitadel init failed; see $RUN/log/zitadel.log" >&2
    tail -n 20 "$RUN/log/zitadel.log" >&2
    exit 1
  }
  setsid nohup "$RUN/zitadel/zitadel" start-from-setup \
    --config "$CONF/zitadel.yaml" --config "$CONF/local.yaml" \
    --steps "$CONF/steps.yaml" \
    --masterkeyFromEnv --tlsMode disabled \
    >>"$RUN/log/zitadel.log" 2>&1 &
  echo $! > "$RUN/zitadel.pid"
fi

printf 'waiting for zitadel'
i=0
until curl -fs -o /dev/null http://localhost:8090/debug/ready; do
  i=$((i + 1))
  if [ "$i" -gt 180 ] || ! running zitadel; then
    echo; echo "zitadel did not become ready; see $RUN/log/zitadel.log" >&2
    tail -n 30 "$RUN/log/zitadel.log" >&2
    exit 1
  fi
  printf .; sleep 1
done
echo " ready"
chmod 600 "$SECRETS"/*.pat 2>/dev/null || true

# --- idlogin ---------------------------------------------------------------
(cd "$ROOT" && go build -trimpath -o "$RUN/bin/idlogin" ./cmd/idlogin)

if [ ! -f "$LOGIN_BRANDS_FILE" ]; then
  cat > "$LOGIN_BRANDS_FILE" <<EOF
{
  "brands": [
    {
      "id": "example",
      "name": "Example",
      "hosts": ["localhost:8091"],
      "public_origin": "http://localhost:8091",
      "zitadel_host": "localhost:8090",
      "tagline": "Local development stack.",
      "mail_from": "Example <no-reply@example.com>",
      "login_client_pat_file": "$SECRETS/login-client.pat",
      "return_urls": ["http://localhost:8095/", "http://localhost:3000/"],
      "registration_enabled": true,
      "idps": [{"key": "google", "id": ""}, {"key": "github", "id": ""}]
    }
  ]
}
EOF
fi

# Instance setup the login needs (idempotent): preaccesstoken action target +
# execution, and the OIDC token lifetimes for this existing instance.
"$RUN/bin/idlogin" setup -zitadel http://localhost:8090 -pat-file "$SECRETS/provisioner.pat" \
  -actions-endpoint "http://localhost:8091/login/zitadel/preaccesstoken" \
  -actions-key-file "$LOGIN_ACTIONS_SIGNING_KEY_FILE" >>"$RUN/log/idlogin.log" 2>&1 || {
  echo "idlogin setup failed; see $RUN/log/idlogin.log" >&2
  tail -n 10 "$RUN/log/idlogin.log" >&2
  exit 1
}

if running idlogin; then
  pid="$(cat "$RUN/idlogin.pid")"
  kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
  while kill -0 "$pid" 2>/dev/null; do sleep 0.2; done
fi
setsid nohup "$RUN/bin/idlogin" >>"$RUN/log/idlogin.log" 2>&1 &
echo $! > "$RUN/idlogin.pid"
i=0
until curl -fs -o /dev/null -H 'Host: localhost:8091' "http://$LOGIN_ADDR/login/healthz"; do
  i=$((i + 1))
  if [ "$i" -gt 50 ] || ! running idlogin; then
    echo "idlogin did not start; see $RUN/log/idlogin.log" >&2
    tail -n 20 "$RUN/log/idlogin.log" >&2
    exit 1
  fi
  sleep 0.2
done

cat <<EOF

Zitadel console  http://localhost:8090/ui/console  (signs in through idlogin)
Sign-in service  http://localhost:8091/login        (idlogin, brands: $LOGIN_BRANDS_FILE)
OIDC issuer      http://localhost:8090
Admin user       admin@id.localhost  (password: ZITADEL_FIRSTINSTANCE_ORG_HUMAN_PASSWORD in $ENV)
Dev mail         $LOGIN_MAIL_DIR
Logs             $RUN/log/
State            $RUN  (IDLOGIN_DEV_HOME)
EOF
