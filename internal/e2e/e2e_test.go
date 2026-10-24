// Package e2e drives the real local stack (scripts/dev-up.sh: Zitadel on
// :8090, idlogin on :8091) with an HTTP client, through a minimal in-test
// relying party on :8095 (rp_test.go). It only runs with LOGIN_E2E=1:
//
//	scripts/dev-up.sh
//	LOGIN_E2E=1 go test -count=1 -v ./internal/e2e
//
// The stack's state (secrets, pid files, logs, mail) is read from
// IDLOGIN_DEV_HOME, default ${XDG_DATA_HOME:-$HOME/.local/share}/idlogin.
//
// It creates fixture users (deleted at the end), a fixture project with three
// apps (the relying party's web app, a native JWT app, and the client of a
// "loopback" generic OIDC IdP that points back at the same Zitadel), and
// temporarily adds that IdP and a second host with registration closed to the
// brands file (SIGHUP; restored after).
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	zitadelURL = "http://localhost:8090"
	loginURL   = "http://localhost:8091"
	closedURL  = "http://127.0.0.1:8091" // same service, brand with registration closed
	rpURL      = "http://localhost:8095"
	nativeCB   = "http://127.0.0.1:8096/callback"
)

type stack struct {
	t        *testing.T
	home     string // IDLOGIN_DEV_HOME
	env      map[string]string
	rp       app // the relying party's web app
	adminPAT string
	loginPAT string
	run      string
	users    []string // fixture user IDs to delete
	emails   []string // addresses whose users to delete
	native   string   // native app client id
	idpID    string
}

func readEnv(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			out[k] = v
		}
	}
	return out, s.Err()
}

// devHome is the local stack's state directory, the same default as
// scripts/dev-up.sh.
func devHome() string {
	if h := os.Getenv("IDLOGIN_DEV_HOME"); h != "" {
		return h
	}
	data := os.Getenv("XDG_DATA_HOME")
	if data == "" {
		home, _ := os.UserHomeDir()
		data = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(data, "idlogin")
}

func newStack(t *testing.T) *stack {
	home := devHome()
	s := &stack{t: t, home: home}
	var err error
	if s.env, err = readEnv(filepath.Join(home, "secrets/local.env")); err != nil {
		t.Fatal(err)
	}
	pat := func(n string) string {
		b, err := os.ReadFile(filepath.Join(home, "secrets", n))
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(b))
	}
	s.adminPAT, s.loginPAT = pat("provisioner.pat"), pat("login-client.pat")
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	s.run = hex.EncodeToString(b)
	for _, u := range []string{zitadelURL + "/debug/ready", loginURL + "/login/healthz"} {
		resp, err := http.Get(u)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s not up (run scripts/dev-up.sh): %v", u, err)
		}
		resp.Body.Close()
	}
	s.rp = s.ensureApp("idlogin-e2e", "e2e-rp", map[string]any{
		"redirectUris": []string{rpURL + "/auth/callback"}, "postLogoutRedirectUris": []string{rpURL + "/"},
		"responseTypes": []string{"OIDC_RESPONSE_TYPE_CODE"},
		"grantTypes":    []string{"OIDC_GRANT_TYPE_AUTHORIZATION_CODE", "OIDC_GRANT_TYPE_REFRESH_TOKEN"},
		"appType":       "OIDC_APP_TYPE_WEB", "authMethodType": "OIDC_AUTH_METHOD_TYPE_BASIC",
		"accessTokenType": "OIDC_TOKEN_TYPE_BEARER", "idTokenUserinfoAssertion": true, "devMode": true,
		"backChannelLogoutUri": rpURL + "/auth/backchannel-logout",
	})
	return s
}

// api calls Zitadel with the provisioner (IAM owner) token.
func (s *stack) api(method, path string, body, out any) error {
	return call(s.adminPAT, method, path, body, out)
}

func call(token, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	for attempt := 0; ; attempt++ {
		if rd != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, zitadelURL+path, rd)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 503 && attempt < 10 {
			time.Sleep(time.Second)
			continue
		}
		if resp.StatusCode/100 != 2 {
			return fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, raw)
		}
		if out != nil {
			return json.Unmarshal(raw, out)
		}
		return nil
	}
}

func (s *stack) email(tag string) string {
	e := fmt.Sprintf("e2e-%s-%s@login.test", s.run, tag)
	s.emails = append(s.emails, e)
	return e
}

// fixtureUser creates a human user; password "" means passwordless.
func (s *stack) fixtureUser(email, password string, verified bool) string {
	s.t.Helper()
	body := map[string]any{
		"username": email,
		"profile":  map[string]string{"givenName": "E2E", "familyName": "Fixture"},
		"email":    map[string]any{"email": email, "isVerified": verified},
	}
	if password != "" {
		body["password"] = map[string]any{"password": password, "changeRequired": false}
	}
	var out struct {
		UserID string `json:"userId"`
	}
	if err := s.api("POST", "/v2/users/human", body, &out); err != nil {
		s.t.Fatal(err)
	}
	s.users = append(s.users, out.UserID)
	return out.UserID
}

type zuser struct {
	UserID string `json:"userId"`
	Human  struct {
		Email struct {
			Email      string `json:"email"`
			IsVerified bool   `json:"isVerified"`
		} `json:"email"`
	} `json:"human"`
}

func (s *stack) findUser(email string) *zuser {
	var out struct {
		Result []zuser `json:"result"`
	}
	if err := s.api("POST", "/v2/users", map[string]any{"queries": []any{map[string]any{
		"emailQuery": map[string]string{"emailAddress": email, "method": "TEXT_QUERY_METHOD_EQUALS_IGNORE_CASE"}}}}, &out); err != nil {
		s.t.Fatal(err)
	}
	if len(out.Result) == 0 {
		return nil
	}
	return &out.Result[0]
}

func (s *stack) authMethods(uid string) []string {
	var out struct {
		Types []string `json:"authMethodTypes"`
	}
	if err := s.api("GET", "/v2/users/"+uid+"/authentication_methods", nil, &out); err != nil {
		s.t.Fatal(err)
	}
	return out.Types
}

func (s *stack) cleanup() {
	for _, e := range s.emails {
		if u := s.findUser(e); u != nil && !slices.Contains(s.users, u.UserID) {
			s.users = append(s.users, u.UserID)
		}
	}
	for _, id := range s.users {
		if err := s.api("DELETE", "/v2/users/"+id, nil, nil); err != nil && !strings.Contains(err.Error(), "404") {
			s.t.Logf("delete user %s: %v", id, err)
		}
	}
}

// resetIPLimits clears the per-IP rate-limit windows for loopback, so
// repeated e2e runs within an hour do not hit them (per-address limits are
// per fixture address and stay untouched).
func (s *stack) resetIPLimits() {
	ctx := context.Background()
	cfg, err := pgx.ParseConfig(s.env["LOGIN_DATABASE_URL"])
	if err != nil {
		s.t.Fatal(err)
	}
	cfg.Password = s.env["LOGIN_DATABASE_PASSWORD"]
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		s.t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `DELETE FROM login_rate_events WHERE key LIKE '%:ip:127.0.0.1' OR key LIKE '%:ip:::1'`); err != nil {
		s.t.Fatal(err)
	}
}

var codeRe = regexp.MustCompile(`(?m)^\s*(\d{6})\s*$`)

// mailFiles lists the dev mailer's .txt files for an address, oldest first.
func (s *stack) mailFiles(to string) []string {
	files, _ := filepath.Glob(filepath.Join(s.env["LOGIN_MAIL_DIR"], "*-"+strings.ToLower(to)+".txt"))
	sort.Strings(files)
	return files
}

// code returns the code of the newest mail to an address.
func (s *stack) code(to string) string {
	s.t.Helper()
	files := s.mailFiles(to)
	if len(files) == 0 {
		s.t.Fatalf("no mail for %s", to)
	}
	b, _ := os.ReadFile(files[len(files)-1])
	m := codeRe.FindStringSubmatch(string(b))
	if m == nil {
		s.t.Fatalf("no code in %s", files[len(files)-1])
	}
	return m[1]
}

type app struct {
	ClientID, ClientSecret string
}

// ensureApp creates or updates an OIDC app in the fixture project. A new
// secret is generated for confidential apps on every run.
func (s *stack) ensureApp(project, name string, cfg map[string]any) app {
	t := s.t
	var projects struct {
		Result []struct{ ID, Name string } `json:"result"`
	}
	if err := s.api("POST", "/management/v1/projects/_search", map[string]any{"queries": []any{map[string]any{
		"nameQuery": map[string]string{"name": project, "method": "TEXT_QUERY_METHOD_EQUALS"}}}}, &projects); err != nil {
		t.Fatal(err)
	}
	var pid string
	for _, p := range projects.Result {
		if p.Name == project {
			pid = p.ID
		}
	}
	if pid == "" {
		var out struct{ ID string }
		if err := s.api("POST", "/management/v1/projects", map[string]any{"name": project}, &out); err != nil {
			t.Fatal(err)
		}
		pid = out.ID
	}
	var apps struct {
		Result []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			OIDCConfig struct {
				ClientID string `json:"clientId"`
			} `json:"oidcConfig"`
		} `json:"result"`
	}
	if err := s.api("POST", "/management/v1/projects/"+pid+"/apps/_search", map[string]any{}, &apps); err != nil {
		t.Fatal(err)
	}
	for _, a := range apps.Result {
		if a.Name != name {
			continue
		}
		if err := s.api("PUT", "/management/v1/projects/"+pid+"/apps/"+a.ID+"/oidc_config", cfg, nil); err != nil && !strings.Contains(err.Error(), "No changes") {
			t.Fatal(err)
		}
		out := app{ClientID: a.OIDCConfig.ClientID}
		if cfg["authMethodType"] != "OIDC_AUTH_METHOD_TYPE_NONE" {
			var sec struct {
				ClientSecret string `json:"clientSecret"`
			}
			if err := s.api("POST", "/management/v1/projects/"+pid+"/apps/"+a.ID+"/oidc_config/_generate_client_secret", map[string]any{}, &sec); err != nil {
				t.Fatal(err)
			}
			out.ClientSecret = sec.ClientSecret
		}
		return out
	}
	body := map[string]any{"name": name}
	for k, v := range cfg {
		body[k] = v
	}
	var out struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
	}
	if err := s.api("POST", "/management/v1/projects/"+pid+"/apps/oidc", body, &out); err != nil {
		t.Fatal(err)
	}
	return app{ClientID: out.ClientID, ClientSecret: out.ClientSecret}
}

// ensureLoopbackIdP registers a generic OIDC IdP whose provider is this very
// Zitadel instance, with its own client app.
func (s *stack) ensureLoopbackIdP() string {
	t := s.t
	client := s.ensureApp("idlogin-e2e", "loopback-idp", map[string]any{
		"redirectUris": []string{zitadelURL + "/idps/callback"}, "responseTypes": []string{"OIDC_RESPONSE_TYPE_CODE"},
		"grantTypes": []string{"OIDC_GRANT_TYPE_AUTHORIZATION_CODE"}, "appType": "OIDC_APP_TYPE_WEB",
		"authMethodType": "OIDC_AUTH_METHOD_TYPE_BASIC", "devMode": true, "idTokenUserinfoAssertion": true,
	})
	cfg := map[string]any{
		"name": "e2e-loopback", "issuer": zitadelURL, "clientId": client.ClientID, "clientSecret": client.ClientSecret,
		"scopes": []string{"openid", "profile", "email"}, "isIdTokenMapping": false,
		"providerOptions": map[string]any{"isLinkingAllowed": true, "isCreationAllowed": true},
	}
	var found struct {
		Result []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"result"`
	}
	if err := s.api("POST", "/admin/v1/idps/templates/_search", map[string]any{"queries": []any{map[string]any{
		"idpNameQuery": map[string]string{"name": "e2e-loopback", "method": "TEXT_QUERY_METHOD_EQUALS"}}}}, &found); err != nil {
		t.Fatal(err)
	}
	for _, f := range found.Result {
		if f.Name == "e2e-loopback" {
			if err := s.api("PUT", "/admin/v1/idps/generic_oidc/"+f.ID, cfg, nil); err != nil && !strings.Contains(err.Error(), "No changes") {
				t.Fatal(err)
			}
			return f.ID
		}
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := s.api("POST", "/admin/v1/idps/generic_oidc", cfg, &out); err != nil {
		t.Fatal(err)
	}
	return out.ID
}

// overrideBrands adds the loopback IdP and a registration-closed host to the
// brands file and reloads idlogin; the original is restored on cleanup.
func (s *stack) overrideBrands(idpID string) {
	t := s.t
	path := s.env["LOGIN_BRANDS_FILE"]
	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Brands []map[string]any `json:"brands"`
	}
	if err := json.Unmarshal(orig, &doc); err != nil {
		t.Fatal(err)
	}
	open := doc.Brands[0]
	idps, _ := open["idps"].([]any)
	open["idps"] = append(idps, map[string]any{"key": "e2e", "id": idpID, "label": "Loopback IdP"})
	closed := map[string]any{}
	for k, v := range open {
		closed[k] = v
	}
	closed["id"] = fmt.Sprint(open["id"]) + "-closed"
	closed["hosts"] = []string{"127.0.0.1:8091"}
	closed["public_origin"] = closedURL
	closed["registration_enabled"] = false
	doc.Brands = append([]map[string]any{open}, closed)
	b, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	s.reload()
	t.Cleanup(func() {
		_ = os.WriteFile(path, orig, 0o600)
		s.reload()
	})
}

func (s *stack) reload() {
	b, err := os.ReadFile(filepath.Join(s.home, "idlogin.pid"))
	if err != nil {
		s.t.Fatal(err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
		s.t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
}

func pkce() (verifier, challenge string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(h[:])
}

// authorizeURL builds an authorization request by hand (for prompt tests
// and apps other than the example).
func authorizeURL(clientID, redirect, scope, challenge string, extra map[string]string) string {
	q := url.Values{"client_id": {clientID}, "response_type": {"code"}, "scope": {scope}, "redirect_uri": {redirect},
		"state": {"e2e-state"}, "nonce": {"n"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	for k, v := range extra {
		q.Set(k, v)
	}
	return zitadelURL + "/oauth/v2/authorize?" + q.Encode()
}

type tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Error        string `json:"error"`
}

func tokenRequest(form url.Values, clientID, secret string) (tokens, int) {
	req, _ := http.NewRequest("POST", zitadelURL+"/oauth/v2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if secret != "" {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))
	} else {
		form.Set("client_id", clientID)
		req.Body = io.NopCloser(strings.NewReader(form.Encode()))
		req.ContentLength = int64(len(form.Encode()))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return tokens{Error: err.Error()}, 0
	}
	defer resp.Body.Close()
	var t tokens
	_ = json.NewDecoder(resp.Body).Decode(&t)
	return t, resp.StatusCode
}

func jwtClaims(t *testing.T, tok string) map[string]any {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("access token is not a JWT: %.40s", tok)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	_ = json.Unmarshal(b, &c)
	return c
}

func httpGetJSON(u string, out any) (*http.Response, error) {
	resp, err := http.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return resp, json.NewDecoder(resp.Body).Decode(out)
}
